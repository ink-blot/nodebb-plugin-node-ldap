(function(module) {
    "use strict";
    /* globals app, socket */
    var user           = module.parent.require('./user'),
        meta           = module.parent.require('./meta'),
        db             = module.parent.require('./database'),
        winston        = module.parent.require('winston'),
        passport       = module.parent.require('passport'),
        fs             = module.parent.require('fs'),
        path           = module.parent.require('path'),
        nconf          = module.parent.require('nconf'),
        async          = module.parent.require('async'),
        local_strategy = module.parent.require('passport-local').Strategy,
        ldapjs         = require('ldapjs');

    var master_config = {};
    var node_ldap = {
        name: "Node LDAP",
        get_domain: function (base) {
            var domain = '';
            if (base !== '') {
                var temp = base.match(/dc=([^,]*)/gi);
                if (temp && temp.length > 0) {
                    domain = temp.map(function (str) {
                        return str.match(/dc=([^,]*)/i)[1];
                    }).reduce(function (current, previous) {
                        return current + '.' + previous;
                    });
                }
            }
            return domain;
        },

        admin: function (custom_header, callback) {
            custom_header.plugins.push({
                "route": "/plugins/node_ldap",
                "icon": "fa-cog",
                "name": "LDAP Settings"
            });
            callback(null, custom_header);
        },

        init: function(params, callback) {
            function render(req, res, next) {
                res.render('node_ldap', {});
            }

            meta.settings.get('nodeldap', function(err, options) {
                master_config = options;
            });
            params.router.get('/admin/plugins/node_ldap', params.middleware.admin.buildHeader, render);
            params.router.get('/api/admin/plugins/node_ldap', render);

            callback();
        },

        get_config: function(options, callback) {
            meta.settings.get('nodeldap', function(err, settings) {
                if (err) {
                    return callback(null, options);
                }
                master_config = settings;
                options.nodeldap = settings;
                callback(null, options);
            });
        },

        fetch_config: function(callback) {
            meta.settings.get('nodeldap', function(err, options) {
                callback(options);
            });
        },

        murmurhash3_32_gc: function(key, seed) {
            seed = seed || 12345;
            var remainder, bytes, h1, h1b, c1, c1b, c2, c2b, k1, i;

            remainder = key.length & 3; // key.length % 4
            bytes = key.length - remainder;
            h1 = seed;
            c1 = 0xcc9e2d51;
            c2 = 0x1b873593;
            i = 0;

            while (i < bytes) {
                k1 = ((key.charCodeAt(i) & 0xff)) | ((key.charCodeAt(++i) & 0xff) << 8) | ((key.charCodeAt(++i) & 0xff) << 16) | ((key.charCodeAt(++i) & 0xff) << 24);
                ++i;

                k1 = ((((k1 & 0xffff) * c1) + ((((k1 >>> 16) * c1) & 0xffff) << 16))) & 0xffffffff;
                k1 = (k1 << 15) | (k1 >>> 17);
                k1 = ((((k1 & 0xffff) * c2) + ((((k1 >>> 16) * c2) & 0xffff) << 16))) & 0xffffffff;

                h1 ^= k1;
                h1 = (h1 << 13) | (h1 >>> 19);
                h1b = ((((h1 & 0xffff) * 5) + ((((h1 >>> 16) * 5) & 0xffff) << 16))) & 0xffffffff;
                h1 = (((h1b & 0xffff) + 0x6b64) + ((((h1b >>> 16) + 0xe654) & 0xffff) << 16));
            }

            k1 = 0;

            switch (remainder) {
                case 3: k1 ^= (key.charCodeAt(i + 2) & 0xff) << 16; break;
                case 2: k1 ^= (key.charCodeAt(i + 1) & 0xff) << 8; break;
                case 1: k1 ^= (key.charCodeAt(i) & 0xff);
                        k1 = (((k1 & 0xffff) * c1) + ((((k1 >>> 16) * c1) & 0xffff) << 16)) & 0xffffffff;
                        k1 = (k1 << 15) | (k1 >>> 17);
                        k1 = (((k1 & 0xffff) * c2) + ((((k1 >>> 16) * c2) & 0xffff) << 16)) & 0xffffffff;
                        h1 ^= k1;
                        break;
            }

            h1 ^= key.length;
            h1 ^= h1 >>> 16;
            h1 = (((h1 & 0xffff) * 0x85ebca6b) + ((((h1 >>> 16) * 0x85ebca6b) & 0xffff) << 16)) & 0xffffffff;
            h1 ^= h1 >>> 13;
            h1 = ((((h1 & 0xffff) * 0xc2b2ae35) + ((((h1 >>> 16) * 0xc2b2ae35) & 0xffff) << 16))) & 0xffffffff;
            h1 ^= h1 >>> 16;

            return h1 >>> 0;
        },

        stringtoint: function (str) {
            return str.split('').map(function (char) {
                return char.charCodeAt(0);
            }).reduce(function (current, previous) {
                return previous + current;
            });
        },

        override: function () {
            passport.use(new local_strategy({
                passReqToCallback: true
            }, function (req, username, password, next) {
                if (!username) {
                    return next(new Error('[[error:invalid-username]]'));
                }
                if (!password) {
                    return next(new Error('[[error:invalid-password]]'));
                }
                if (typeof master_config.server === 'undefined') {
                    node_ldap.fetch_config(function(config) {
                        var options = {
                            url: config.server + ':' + config.port,
                        };
                        master_config = config;
                        node_ldap.process(options, username, password, next);
                    });
                } else {
                    var options = {
                        url: master_config.server + ':' + master_config.port,
                    };
                    node_ldap.process(options, username, password, next);
                }
            }));
        },

        process: function(options, username, password, next) {
            try {               
                var client = ldapjs.createClient(options);
                var userdetails = username.split('@');
                if (userdetails.length == 1) {

                    username = username.trim();

                    var opts3 = { 
                      filter: '&('+master_config.filter+'='+username+')',
                      scope: 'sub',
                      sizeLimit: 1
                    };                
                    
                    client.search(master_config.base, opts3, function(err, res) {
                          if (err) {
                            return next(new Error('[[error:invalid-username]]'));
                          }
                          res.on('searchEntry', function(entry) {
                                var profile3 = entry.object;
                                bind_and_search(profile3);
                          });

                          res.on('error', function(err) {
                                winston.error('Node LDAP Error:' + err.message);
                                return next(new Error('[[error:invalid-username]]'));
                          });
                    });                                      
                }

                if (userdetails.length > 1) {

                    username = username.trim();
                    var opts2 = {
                      filter: '&(mail='+username+')',
                      scope: 'sub',
                      sizeLimit: 1
                    };                
                    
                    client.search(master_config.base, opts2, function(err, res) {
                          if (err) {
                            return next(new Error('[[error:invalid-username]]'));
                          }
                          res.on('searchEntry', function(entry) {
                                var profile2 = entry.object;
                                bind_and_search(profile2);
                          });

                          res.on('error', function(err) {
                                winston.error('Node LDAP Error:' + err.message);
                                return next(new Error('[[error:invalid-email]]'));
                          });                    
                    
                      
                    });                    
                }

                function bind_and_search (profilez) {
                    var username=profilez[master_config.filter];
                    username = master_config.filter+'='+username+','+master_config.base;
                    client.bind(username, password, function(err) {
                        if (err) {
                            winston.error(err.message);
                            return next(new Error('[[error:invalid-password]]'));
                        }
                        var openldap_filter1= username.split(',');
                        openldap_filter1=openldap_filter1[0];
                        var openldap_filter2= openldap_filter1.split('=');
                        openldap_filter1=openldap_filter2[1];
                        openldap_filter1 = openldap_filter1.trim();
                        var opt = {filter: '(&(' + master_config.filter + '=' + openldap_filter1 + '))',
                        scope: 'sub',
                        sizeLimit: 1
                        };
                        var str2 = JSON.stringify(opt, null, 4);
                        client.search(master_config.base, opt, function (err, res) {
                            if (err) {
                                return next(new Error('[[error:invalid-username]]'));
                            }

                            res.on('searchEntry', function(entry) {
                                var profile = entry.object;
                                var id = node_ldap.murmurhash3_32_gc(profile[master_config.dname]);
                                if (!profile.mail) {
                                    
                                }                              

                                node_ldap.login(id, openldap_filter1, profile, function (err, userObject) {
                                    if (err) {
                                        winston.error(err);
                                        return next(new Error('[[error:invalid-email]]'));
                                    }
                                    return next(null, userObject);
                                });
                            });

                            res.on('error', function(err) {
                                winston.error('Node LDAP Error:' + err.message);
                                return next(new Error('[[error:invalid-email]]'));
                            });
                        });
                    });
                }

            } catch (err) {
                winston.error('Node LDAP Error :' +  err.message);
            }
        },

        login: function (ldapid, username, profile, callback) {
            var _self = this;
            var displayname=profile[master_config.dname];           
            var email=profile.mail;           
            
            _self.getuidby_ldapid(ldapid, function (err, uid) {
                if (err) {
                    return callback(err);
                }

                if (uid !== null) {
                    return callback(null, {
                        uid: uid
                    });
                    
                } else {
                    // New User
                    var success = function (uid) {
                        // Save provider-specific information to the user
                        user.setUserField(uid, 'ldapid', ldapid);
                        db.setObjectField('ldapid:uid', ldapid, uid);
                        callback(null, {
                            uid: uid
                        });

                        
                    };
                  
                    return user.getUidByEmail(email, function (err, uid) {
                        if (err) {
                            return callback(err);
                        }

                        if (!uid) {
                            var pattern = new RegExp(/[\ ]*\(.*\)/);
                            if (pattern.test(username)) {
                                username = username.replace(pattern, '');
                            }                           
                            var fullnamez=profile[master_config.gname]+' '+profile[master_config.sname];
                            return user.create({username: displayname, fullname: fullnamez, email: email}, function (err, uid) {
                                if (err) {
                                    return callback(err);
                                }
                                if (master_config.autovalidate == 1) {
                                    user.setUserField(uid, 'email:confirmed', 1);
                                }                            
                                return success(uid);
                            });
                        } else {
                          
                            return success(uid); // Existing account -- merge
                        }
                    });
                }
            });
        },
        
        getuidby_ldapid: function (ldapid, callback) {
            db.getObjectField('ldapid:uid', ldapid, function (err, uid) {
                if (err) {
                    return callback(err);
                }

                db.getObject('user:'+uid, function (err, userldapid) {
                    var luid = null;
                    if(userldapid){
                        luid=userldapid.uid;
                    }
                    if (err) {
                        return callback(err);
                    }
                    return callback(null, luid);
                });
            });
        }      
        
    };
    module.exports = node_ldap;

}(module));
