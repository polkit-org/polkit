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

polkit._adminRuleFuncs = [];
polkit.addAdminRule = function(callback) {this._adminRuleFuncs.push(callback);};
polkit._runAdminRules = function(action, subject, details) {
    var ret = null;
    for (var n = this._adminRuleFuncs.length - 1; n >= 0; n--) {
        var func = this._adminRuleFuncs[n];
        var func_ret = func(action, subject, details);
        if (func_ret) {
            ret = func_ret;
            break
        }
    }
    return ret.join(",");
};

polkit._ruleFuncs = [];
polkit.addRule = function(callback) {this._ruleFuncs.push(callback);};
polkit._runRules = function(action, subject, details) {
    var ret = null;
    for (var n = this._ruleFuncs.length - 1; n >= 0; n--) {
        var func = this._ruleFuncs[n];
        var func_ret = func(action, subject, details);
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
