/* -*- mode: js; js-indent-level: 4; indent-tabs-mode: nil -*- */

function Details() {
    this.toString = function() {
        var ret = "[Details";
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

function Subject() {

    this.isInGroup = function(group) {
        for (var n = 0; n < this.groups.length; n++) {
            if (this.groups[n] == group)
                return true;
        }
        return false;
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

polkit._administratorRuleFuncs = [];
polkit.addAdministratorRule = function(callback) {this._administratorRuleFuncs.push(callback);};
polkit._runAdministratorRules = function(action, subject, details) {
    var ret = null;
    for (var n = this._administratorRuleFuncs.length - 1; n >= 0; n--) {
        var func = this._administratorRuleFuncs[n];
        ret = func(action, subject, details);
        if (ret)
            break
    }
    return ret.join(",");
};

polkit._authorizationRuleFuncs = [];
polkit.addAuthorizationRule = function(callback) {this._authorizationRuleFuncs.push(callback);};
polkit._runAuthorizationRules = function(action, subject, details) {
    var ret = null;
    for (var n = this._authorizationRuleFuncs.length - 1; n >= 0; n--) {
        var func = this._authorizationRuleFuncs[n];
        ret = func(action, subject, details);
        if (ret)
            break
    }
    return ret;
};

polkit._deleteRules = function() {
    this._administratorRuleFuncs = [];
    this._authorizationRuleFuncs = [];
};

