local cjson = require "cjson"
local cjson_safe = require "cjson.safe"
local jwt = require "resty.jwt"

local authcommon = require "auth.common"
local util = require "util"

local SECRET_KEY = nil

local key_file_path = os.getenv("SECRET_KEY_FILE_PATH")
if key_file_path == nil then
    ngx.log(ngx.WARN, "SECRET_KEY_FILE_PATH not set.")
else
    ngx.log(ngx.NOTICE, "Reading secret key from `" .. key_file_path .. "`.")
    if os.getenv("JWT_ALG") == "RS256" then
        SECRET_KEY = util.get_file_content(key_file_path)
        jwt:set_alg_whitelist({RS256=1})
    else
        SECRET_KEY = util.get_stripped_first_line_from_file(key_file_path)
        jwt:set_alg_whitelist({HS256=1})
    end
    if (SECRET_KEY == nil or SECRET_KEY == '') then
        -- Normalize to nil, for simplified subsequent per-request check.
        SECRET_KEY = nil
        ngx.log(ngx.WARN, "Secret key not set or empty string.")
    end
end


local function timestamp_iso8601()
    -- Get time string in format yyyy-mm-dd hh:mm:ss
    -- then replace the space with a 'T' and append 'Z'.
    local t = ngx.utctime()
    t = t:gsub(" ", "T")
    return t .. "Z"
end


local function auditlog(params)
    local timestamp = timestamp_iso8601()
    local auditlogstring = 'type=audit' ..
        ' timestamp=' .. timestamp ..
        ' authorizer=adminrouter' ..
        ' object=' .. params.object ..
        ' action=' .. params.action ..
        ' result=' .. params.result ..
        ' reason="' .. params.reason .. '"' ..
        ' srcip=' .. ngx.var.remote_addr ..
        ' srcport=' .. ngx.var.remote_port ..
        ' request_uri=' .. ngx.var.request_uri

    -- For non-authenticated requests, uid is not set.
    if params["uid"] ~= nil then
        auditlogstring = auditlogstring .. ' uid=' .. params.uid
    end

    ngx.log(ngx.NOTICE, auditlogstring)
end


local function audited_exit_401(object, action)
    -- Log that operation is denied.
    local auditlogparms = {
        object = object,
        action = action,
        result = "deny",
        reason = "not authenticated"
        }
    auditlog(auditlogparms)

    return authcommon.exit_401("acsjwt")
end


local function audited_exit_403(uid, object, action, reason)
    -- Log that operation is denied.
    local auditlogparms = {
        uid = uid,
        object = object,
        action = action,
        result = "deny",
        reason = reason
        }
    auditlog(auditlogparms)

    return authcommon.exit_403()
end


local function validate_jwt_or_exit(object, action)
    uid, err = authcommon.validate_jwt(SECRET_KEY)
    if err ~= nil then
        if err == 401 then
            return audited_exit_401(object, action)
        end

        -- Other error statuses go here...

        -- Catch-all, normally not reached:
        ngx.log(ngx.ERR, "Unexpected result from validate_jwt()")
        ngx.status = ngx.HTTP_INTERNAL_SERVER_ERROR
        return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end
    return uid
end


local function check_access_control_entry_or_exit(triple)
    -- Check if user <uid> is allowed to perform action <action> on resource
    -- <rid>. Do this by asking iam's policyquery endpoint. Terminate
    -- request handling upon error or when access is forbidden (return
    -- appropriate status code in both cases). Do not terminate request handling
    -- when action is allowed.

    local uid = triple.uid
    local rid = triple.rid
    local action = triple.action

    -- Build URL pointing to internal policyquery endpoint served by iam.
    local url = "/internal/acs/api/v1/internal/policyquery?rid=" ..
        rid .. "&uid=" .. uid .. "&action=" .. action
    ngx.log(ngx.NOTICE, "Consult policyquery via `".. url .. "`")

    -- So, defer this to iam with a subrequest.
    -- Ref: https://github.com/openresty/lua-nginx-module#ngxlocationcapture
    res = ngx.location.capture(url)
    ngx.log(ngx.DEBUG, "JSONnized response: " .. cjson.encode(res))

    -- Expect 200 response, with JSON body having `allowed` object.
    if res.status ~= ngx.HTTP_OK then
        ngx.log(
            ngx.NOTICE,
            "Unexpected policyquery response status (JSONized): " ..
            cjson.encode(res)
            )
        -- When using say/print, set status beforehand.
        -- Cf. https://github.com/openresty/lua-nginx-module#ngxprint
        ngx.status = ngx.HTTP_INTERNAL_SERVER_ERROR
        ngx.say("Unexpected policyquery response.")
        return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end

    local respdata = cjson_safe.decode(res.body)
    ngx.log(
        ngx.DEBUG,
        "JSONdecoded response body, JSONized: " ..
        cjson.encode(respdata)
        )

    if respdata == nil then
        ngx.log(
            ngx.NOTICE,
            "JSONdecode failed. Response: " ..
            cjson.encode(res)
            )

        ngx.status = ngx.HTTP_INTERNAL_SERVER_ERROR
        ngx.say("Unexpected policyquery response.")
        return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end

    if respdata.allowed == nil then
        ngx.log(
            ngx.NOTICE,
            "`allowed` not in JSONdecoded response: " ..
            cjson.encode(res)
            )
        ngx.status = ngx.HTTP_INTERNAL_SERVER_ERROR
        ngx.say("Unexpected policyquery response.")
        return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    end

    -- Make resource ID available as `object`, which is
    -- how it's called in the audit log.
    local object = rid

    if respdata.allowed == false then
        local reason = "IAM PQ response"
        return audited_exit_403(uid, object, action, reason)
    end

    -- Log that operation is allowed.
    local auditlogparms = {
        uid = uid,
        object = object,
        action = action,
        result = "allow",
        reason = "IAM PQ response"
        }
    auditlog(auditlogparms)
end


local function do_authn_and_authz_or_exit(resource_id)
    -- Helper function for extracting identity from token, and for checking
    -- 'full' action against ACL for resoruce with id rid.
    local object = resource_id
    local action = "full"
    local uid = validate_jwt_or_exit(object, action)
    local triple = {
        uid = uid,
        rid = object,
        action = action
        }
    check_access_control_entry_or_exit(triple)
end


local function do_authn_or_exit(object)
      -- This function only ensures that the user is authenticated
      -- and logs the fact of accessing given RID to audit log.
      -- Authorization, if necessary, is done in different parts of
      -- the system.
      local action = "full"
      local uid = validate_jwt_or_exit(object, action)

      local auditlogparms = {
          uid = uid,
          object = object,
          action = action,
          result = "allow",
          reason = "authenticated (all users are allowed to access)"
          }
      auth.auditlog(auditlogparms)
  end


-- Initialise and return the module:
local _M = {}
function _M.init(use_auth)
    local res = {}

    res.auditlog = auditlog

    if use_auth == "false" then
        ngx.log(
            ngx.NOTICE,
            "ADMINROUTER_ACTIVATE_AUTH_MODULE set to `false`. " ..
            "Deactivate authentication module."
            )
        res.auditlog = function() return end
        res.check_access_control_entry_or_exit = function(x) return end
        res.do_authn_and_authz_or_exit = function(x) return end
        res.do_authn_or_exit = function(x) return end
        res.exit_403 = function(x) return end
        res.validate_jwt_or_exit = function() return end
    else
        ngx.log(ngx.NOTICE, "Activate authentication module.");
        res.auditlog = auditlog
        res.check_access_control_entry_or_exit = check_access_control_entry_or_exit
        res.do_authn_and_authz_or_exit = do_authn_and_authz_or_exit
        res.do_authn_or_exit = do_authn_or_exit
        res.exit_403 = audited_exit_403
        res.validate_jwt_or_exit = validate_jwt_or_exit
    end

    -- /acs/acl-schema.json
    res.access_aclschema_endpoint = function()
        return res.do_authn_and_authz_or_exit("dcos:adminrouter:acs");
    end

    -- /ca/api/v2/certificates
    res.access_cacertificates_endpoint = function()
        return res.do_authn_and_authz_or_exit("dcos:adminrouter:ops:ca:ro");
    end

    -- /ca/api/v2/bundle
    res.access_cabundle_endpoint = function()
        return res.do_authn_and_authz_or_exit("dcos:adminrouter:ops:ca:ro");
    end

    -- /ca/api/v2/(newcert|newkey|sign)
    res.access_carw_endpoint = function()
        return res.do_authn_and_authz_or_exit("dcos:adminrouter:ops:ca:rw");
    end

    -- ^/(slave|agent)/(?<agentid>[0-9a-zA-Z-]+)(?<url>.+)$
    res.access_agent_endpoint = function()
        return res.do_authn_and_authz_or_exit("dcos:adminrouter:ops:slave");
    end

    -- /mesos/
    res.access_mesos_endpoint = function()
        return res.do_authn_and_authz_or_exit("dcos:adminrouter:ops:mesos");
    end

    -- /package/
    res.access_package_endpoint = function()
        return res.do_authn_and_authz_or_exit("dcos:adminrouter:package");
    end

    -- /capabilities/
    res.access_capabilities_endpoint = function()
        return res.do_authn_or_exit("dcos:adminrouter:capabilities");
    end

    -- /cosmos/service/
    res.access_cosmosservice_endpoint = function()
        return res.do_authn_and_authz_or_exit("dcos:adminrouter:package");
    end

    -- /exhibitor/
    res.access_exhibitor_endpoint = function()
        return res.do_authn_and_authz_or_exit("dcos:adminrouter:ops:exhibitor");
    end

    -- /networking/api/v1/
    res.access_networkingapi_endpoint = function()
        return res.do_authn_and_authz_or_exit("dcos:adminrouter:ops:networking");
    end

    -- /acs/api/v1
    res.access_acsapi_endpoint = function()
        return res.do_authn_and_authz_or_exit("dcos:adminrouter:acs");
    end

    -- /navstar/lashup/key
    res.access_lashupkey_endpoint = function()
        return res.do_authn_or_exit("dcos:adminrouter:navstar-lashup-key");
    end

    -- /service/.+
    res.access_service_endpoint = function(service_path)
        if service_path ~= nil then
            -- Check access for particular resource:
            local resourceid = "dcos:adminrouter:service:" .. service_path
            return res.do_authn_and_authz_or_exit(resourceid)
        end

        -- Just perform authn, RID "dcos:adminrouter:service" will be used just
        -- for logging/auditing purposes.
        return res.do_authn_or_exit("dcos:adminrouter:service")
    end

    -- /metadata
    res.access_metadata_endpoint = function()
        return res.do_authn_or_exit("dcos:adminrouter:ops:metadata");
    end

    -- /dcos-metadata/bootstrap-config.json
    -- /pkgpanda/active.buildinfo.full.json
    res.access_misc_metadata_endpoint = function()
        return res.do_authn_and_authz_or_exit("dcos:adminrouter:ops:metadata");
    end

    -- /dcos-history-service/
    res.access_historyservice_endpoint = function()
        return res.do_authn_and_authz_or_exit("dcos:adminrouter:ops:historyservice");
    end

    -- /mesos_dns/
    res.access_mesosdns_endpoint = function()
        return res.do_authn_and_authz_or_exit("dcos:adminrouter:ops:mesos-dns");
    end

    -- /secrets/v1/
    res.access_secrets_endpoint = function()
        return res.do_authn_or_exit("dcos:adminrouter:secrets");
    end

    -- /system/backup/v1
    res.access_system_backup_endpoint = function()
        return res.do_authn_and_authz_or_exit("dcos:adminrouter:ops:system-backup");
    end

    -- /system/health/v1
    res.access_system_health_endpoint = function()
        return res.do_authn_and_authz_or_exit("dcos:adminrouter:ops:system-health");
    end

    -- /system/logs
    res.access_system_logs_endpoint = function()
        return res.do_authn_and_authz_or_exit("dcos:adminrouter:ops:system-logs");
    end

    -- /system/metrics/v1
    res.access_system_metrics_endpoint = function()
        return res.do_authn_and_authz_or_exit("dcos:adminrouter:ops:system-metrics");
    end

    -- /pkgpanda/
    res.access_pkgpanda_endpoint = function()
        return res.do_authn_and_authz_or_exit("dcos:adminrouter:ops:pkgpanda");
    end

    -- /system/v1/leader/mesos
    res.access_system_mesosleader_endpoint = function()
        return res.do_authn_or_exit("dcos:adminrouter:system:leader:mesos");
    end

    -- /system/v1/leader/marathon
    res.access_system_marathonleader_endpoint = function()
        return res.do_authn_or_exit("dcos:adminrouter:system:leader:marathon");
    end

    -- /system/v1/agent/
    res.access_system_agent_endpoint = function()
        return res.do_authn_or_exit("dcos:adminrouter:system:agent");
    end

    -- agent:
    -- ^/system/v1/logs/v1/(?<type>range|stream)/framework/(?<framework>.*?)/
    res.access_system_logs_strictagent_endpoint = function()
        return res.do_authn_or_exit("dcos:adminrouter:ops:system-logs");
    end

    -- /cockroachdb/
    res.access_cockroachdb_endpoint = function()
        return res.do_authn_and_authz_or_exit("dcos:adminrouter:ops:cockroachdb");
    end

    return res
end

return _M
