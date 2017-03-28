local cjson = require "cjson"
local cjson_safe = require "cjson.safe"
local jwt = require "resty.jwt"
local jwt_validators = require "resty.jwt-validators"
local cookiejar = require "resty.cookie"


local util = require "common.util"


local SECRET_KEY = nil


local errorpages_dir_path = os.getenv("AUTH_ERROR_PAGE_DIR_PATH")
if errorpages_dir_path == nil then
    ngx.log(ngx.WARN, "AUTH_ERROR_PAGE_DIR_PATH not set.")
else
    local p = errorpages_dir_path .. "/401.html"
    ngx.log(ngx.NOTICE, "Reading 401 response from `" .. p .. "`.")
    BODY_401_ERROR_RESPONSE = util.get_file_content(p)
    if (BODY_401_ERROR_RESPONSE == nil or BODY_401_ERROR_RESPONSE == '') then
        -- Normalize to '', for sending empty response bodies.
        BODY_401_ERROR_RESPONSE = ''
        ngx.log(ngx.WARN, "401 error response is empty.")
    end
    local p = errorpages_dir_path .. "/403.html"
    ngx.log(ngx.NOTICE, "Reading 403 response from `" .. p .. "`.")
    BODY_403_ERROR_RESPONSE = util.get_file_content(p)
    if (BODY_403_ERROR_RESPONSE == nil or BODY_403_ERROR_RESPONSE == '') then
        -- Normalize to '', for sending empty response bodies.
        BODY_403_ERROR_RESPONSE = ''
        ngx.log(ngx.WARN, "403 error response is empty.")
    end
end


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


local function exit_401(object, action)
    -- Log that operation is denied.
    local auditlogparms = {
        object = object,
        action = action,
        result = "deny",
        reason = "not authenticated"
        }
    auditlog(auditlogparms)

    ngx.status = ngx.HTTP_UNAUTHORIZED
    ngx.header["Content-Type"] = "text/html; charset=UTF-8"
    ngx.header["WWW-Authenticate"] = "acsjwt"
    ngx.say(BODY_401_ERROR_RESPONSE)
    return ngx.exit(ngx.HTTP_UNAUTHORIZED)
end


local function exit_403(uid, object, action, reason)
    -- Log that operation is denied.
    local auditlogparms = {
        uid = uid,
        object = object,
        action = action,
        result = "deny",
        reason = reason
        }
    auditlog(auditlogparms)

    ngx.status = ngx.HTTP_FORBIDDEN
    ngx.header["Content-Type"] = "text/html; charset=UTF-8"
    ngx.say(BODY_403_ERROR_RESPONSE)
    return ngx.exit(ngx.HTTP_FORBIDDEN)
end


local function ensure_authentication_or_exit(object)
    -- This function only ensures that the user is authenticated
    -- and logs the fact of accessing given RID to audit log.
    -- Authorization, if necessary, is done in different parts of
    -- the system.
    local action = "full"
    local uid = auth.validate_jwt_or_exit(object, action)

    local auditlogparms = {
        uid = uid,
        object = object,
        action = action,
        result = "allow",
        reason = "authenticated (all users are allowed to access)"
        }
    auth.auditlog(auditlogparms)
end


local function validate_jwt_or_exit(object, action)

    -- Inspect Authorization header in current request. Expect JSON Web Token in
    -- compliance with RFC 7519. Expect `uid` key in payload section. Extract
    -- and return uid. In all other cases, terminate request handling and
    -- respond with an appropriate HTTP error status code.

    -- Refs:
    -- https://github.com/openresty/lua-nginx-module#access_by_lua
    -- https://github.com/SkyLothar/lua-resty-jwt

    if SECRET_KEY == nil then
        ngx.log(ngx.ERR, "Secret key not set. Cannot validate request.")
        return exit_401(object, action)
    end

    local auth_header = ngx.var.http_Authorization
    local token = nil
    if auth_header ~= nil then
        ngx.log(ngx.DEBUG, "Authorization header found. Attempt to extract token.")
        _, _, token = string.find(auth_header, "token=(.+)")
    else
        ngx.log(ngx.DEBUG, "Authorization header not found.")
        -- Presence of Authorization header overrides cookie method entirely.
        -- Read cookie. Note: ngx.var.cookie_* cannot access a cookie with a
        -- dash in its name.
        local cookie, err = cookiejar:new()
        token = cookie:get("dcos-acs-auth-cookie")
        if token == nil then
            ngx.log(ngx.DEBUG, "dcos-acs-auth-cookie not found.")
        else
            ngx.log(
                ngx.DEBUG, "Use token from dcos-acs-auth-cookie, " ..
                "set corresponding Authorization header for upstream."
                )
            ngx.req.set_header("Authorization", "token=" .. token)
        end
    end

    if token == nil then
        ngx.log(ngx.NOTICE, "No auth token in request.")
        return exit_401(object, action)
    end

    -- ngx.log(ngx.DEBUG, "Token: `" .. token .. "`")

    -- By default, lua-resty-jwt does not validate claims.
    -- Build up a claim validation specification.
    -- Implement RFC 7519-compliant exp claim validation,
    -- and require the DC/OS-specific `uid` claim to be present.
    local claim_spec = {
        exp = jwt_validators.opt_is_not_expired(),
        __jwt = jwt_validators.require_one_of({"uid"})
        }

    local jwt_obj = jwt:verify(SECRET_KEY, token, claim_spec)
    ngx.log(ngx.DEBUG, "JSONnized JWT table: " .. cjson.encode(jwt_obj))

    -- .verified is False even for messed up tokens whereas .valid can be nil.
    -- So, use .verified as reference.
    if jwt_obj.verified ~= true then
        ngx.log(ngx.NOTICE, "Invalid token. Reason: ".. jwt_obj.reason)
        return exit_401(object, action)
    end

    ngx.log(ngx.DEBUG, "Valid token. Extract UID from payload.")
    local uid = jwt_obj.payload.uid

    if uid == nil or uid == ngx.null then
        ngx.log(ngx.NOTICE, "Unexpected token payload: missing uid.")
        return exit_401(object, action)
    end

    ngx.log(ngx.NOTICE, "UID from valid JWT: `".. uid .. "`")
    return uid
end


local function check_acl_triple_or_exit(triple)
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
        local reason = "Bouncer PQ response"
        return exit_403(uid, object, action, reason)
    end

    -- Log that operation is allowed.
    local auditlogparms = {
        uid = uid,
        object = object,
        action = action,
        result = "allow",
        reason = "Bouncer PQ response"
        }
    auditlog(auditlogparms)
end


local function check_acl_or_exit(resource_id)
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
    check_acl_triple_or_exit(triple)
end


-- Expose interface.
local _M = {}
_M.validate_jwt_or_exit = validate_jwt_or_exit
_M.check_acl_triple_or_exit = check_acl_triple_or_exit
_M.check_acl_or_exit = check_acl_or_exit
_M.auditlog = auditlog
_M.exit_403 = exit_403
_M.ensure_authentication_or_exit = ensure_authentication_or_exit


return _M
