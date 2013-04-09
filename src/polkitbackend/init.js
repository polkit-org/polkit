/* -*- mode: js; js-indent-level: 4; indent-tabs-mode: nil -*- */

function Action() {
    this.lookup = function(name) {
        return this["_detail_" + name];
    },

    this.toString = function() {
        var ret = "[Action id='" + this.id + "'";
        for (var i in this) {
            if (i.indexOf("_detail_") == 0) {
                var key = i.substr(8);
                var value = this[i];
                ret += " " + key + "='" + value + "'";
            }
        }
        ret += "]";
        return ret;
    };
};

function Subject() {
    this.isInGroup = function(group) {
        for (var n = 0; n < this.groups.length; n++) {
            if (this.groups[n] == group)
                return true;
        }
        return false;
    };

    this.isInNetGroup = function(netGroup) {
        return polkit._userIsInNetGroup(this.user, netGroup);
    };

    this.toString = function() {
        var ret = "[Subject";
        for (var i in this) {
            if (typeof this[i] != "function") {
                if (typeof this[i] == "string")
                    ret += " " + i + "='" + this[i] + "'";
                else
                    ret += " " + i + "=" + this[i];
            }
        }
        ret += "]";
        return ret;
    };
};

polkit._adminRuleFuncs = [];
polkit.addAdminRule = function(callback) {this._adminRuleFuncs.push(callback);};
polkit._runAdminRules = function(action, subject) {
    var ret = null;
    for (var n = 0; n < this._adminRuleFuncs.length; n++) {
        var func = this._adminRuleFuncs[n];
        var func_ret = func(action, subject);
        if (func_ret) {
            ret = func_ret;
            break
        }
    }
    return ret ? ret.join(",") : "";
};

polkit._ruleFuncs = [];
polkit.addRule = function(callback) {this._ruleFuncs.push(callback);};
polkit._runRules = function(action, subject) {
    var ret = null;
    for (var n = 0; n < this._ruleFuncs.length; n++) {
        var func = this._ruleFuncs[n];
        var func_ret = func(action, subject);
        if (func_ret) {
            ret = func_ret;
            break
        }
    }
    return ret;
};

polkit._deleteRules = function() {
    this._adminRuleFuncs = [];
    this._ruleFuncs = [];
};

polkit.Result = {
    NO              : "no",
    YES             : "yes",
    AUTH_SELF       : "auth_self",
    AUTH_SELF_KEEP  : "auth_self_keep",
    AUTH_ADMIN      : "auth_admin",
    AUTH_ADMIN_KEEP : "auth_admin_keep",
    NOT_HANDLED     : null
};
