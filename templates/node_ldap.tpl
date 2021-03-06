<form class="ldap-settings form-horizontal" onsubmit="return false;">
  <div class="row">
    <div class="col-md-12 col-sm-12 col-lg-12">
      <h1 class="page-header"><i class="fa fa-cog"></i> LDAP Settings</h1>
      <div class="col-lg-9 col-md-9 col-sm-8">
        <div class="well well-sm">
          <h4 class="page-header">Server Settings</h4>
          <div class="row">
            <div class="form-group col-md-12 col-sm-12">
              <label class="col-sm-3 control-label" for="server">Server URL</label>
              <div class="col-sm-9">
                <input type="text" id="server" required name="server" title="LDAP server" class="form-control" placeholder="ldap://example.ldap.com">
              </div>
            </div>
            <div class="form-group col-md-12 col-sm-12">
              <label class="col-sm-3 control-label" for="port">Server Port</label>
              <div class="col-sm-9">
                <input type="number" id="port" required name="port" title="Port Number" class="form-control" placeholder="389">
              </div>
            </div>
            <div class="form-group col-md-12 col-sm-12">
              <label class="col-sm-3 control-label" for="base">Base DN</label>
              <div class="col-sm-9">
                <input type="text" id="base" required name="base" title="Base DN" class="form-control" placeholder="ou=group,dc=company,dc=com">
              </div>
            </div>
            <div class="form-group col-md-12 col-sm-12">
              <label class="col-sm-3 control-label" for="filter">Filter</label>
              <div class="col-sm-9">
                <input type="text" id="filter" required name="filter" title="Filter" class="form-control" placeholder="cn">
              </div>
            </div>
            <div class="form-group col-md-12 col-sm-12">
              <label class="col-sm-3 control-label" for="dname">User Name</label>
              <div class="col-sm-9">
                <input type="text" id="dname" required name="dname" title="User Name" class="form-control" placeholder="displayName">
              </div>
            </div>           
            <div class="form-group col-md-12 col-sm-12">
              <label class="col-sm-3 control-label" for="dname">Given Name</label>
              <div class="col-sm-9">
                <input type="text" id="gname" required name="gname" title="Given Name" class="form-control" placeholder="givenName">
              </div>
            </div>         
            <div class="form-group col-md-12 col-sm-12">
              <label class="col-sm-3 control-label" for="dname">Surname</label>
              <div class="col-sm-9">
                <input type="text" id="sname" required name="sname" title="Surname" class="form-control" placeholder="sn">
              </div>
            </div>             
          </div>
        </div>
        <div class="well well-sm">
          <h4 class="page-header">Account Settings</h4>
          <div class="row">
            <div class="form-group col-md-12 col-sm-12">
              <label class="col-sm-3 control-label" for="autovalidate">Auto Validate</label>
              <div class="col-sm-9 checkbox">
                <input type="checkbox" id="autovalidate" name="autovalidate" title="Auto Validate">
              </div>
            </div>
          </div>
        </div>
      </div>
      <div class="form-group col-lg-3 col-md-3 col-sm-4">
        <button class="btn btn-lg btn-primary btn-block" type="button" id="save">
          <i class="fa fa-save"></i> Save Settings
        </button>
      </div>
    </div>
  </div>
</form>

<script>
    require(['settings'], function(Settings) {
        Settings.load('nodeldap', $('.ldap-settings'));
        $('#save').on('click', function() {
            Settings.save('nodeldap', $('.ldap-settings'));
        });
        
    });
</script>
