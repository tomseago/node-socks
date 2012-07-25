var fs = require("fs");
var crypto = require("crypto");

function info() {
    if (module.exports.logger.info) {
        module.exports.logger.info.apply(this, arguments);
    }
}

function error() {
    if (module.exports.logger.error) {
        module.exports.logger.error.apply(this, arguments);
    }
}

function AuthFile(filename) {
    
    this.filename = filename;
        
    this.temp = new Buffer(1024);
    this.users = {};
}
module.exports = AuthFile;

AuthFile.prototype.verifyPassword = function(username, password) {
    
    var entry = this.users[username];
    if (!entry) {
        info("Unknown user %s", username);
        return false;
    }
    
    // Salt and hash the password
    entry.salt.copy(this.temp);
    var c = entry.salt.length;
    
    this.temp.write(password, c, password.length);
    c += password.length;
    
    var shasum = crypto.createHash('sha1');
    shasum.update(this.temp.slice(0, c));
    var hashed = shasum.digest("base64");
    
    if (entry.sha1 === hashed) {
        return true;
    }
    
    info("Bad password from %s", username);
    return false;
}

AuthFile.prototype.setUser = function(username, password) {
    var entry = {
        salt: crypto.randomBytes(21)
    }
    
    entry.salt.copy(this.temp);
    var c = entry.salt.length;
    
    this.temp.write(password, c, password.length);
    c += password.length;
    
    var shasum = crypto.createHash('sha1');
    shasum.update(this.temp.slice(0, c));
    entry.sha1 = shasum.digest("base64");
    
    this.users[username] = entry;
}

AuthFile.prototype.removeUser = function(username) {
    delete this.users[username];
}

AuthFile.prototype.readFile = function() {
    var raw = fs.readFileSync(this.filename, "utf8");

    var users = this.users = {};
    var lines = raw.split("\n");
    var count = 0;
    lines.forEach(function(line) {
        var l = line.split(",");
        
        if (!l || l.length<2) return;

        users[l[0]] = {
            salt: new Buffer(l[1], "base64")
            , sha1: l[2]
        }
        count++;
    });
    
    info("Loaded %d users", count);    
}

AuthFile.prototype.writeFile = function() {
    var lines = [];
    
    for(user in this.users) {
        var entry = this.users[user];

        var line = user + "," + entry.salt.toString("base64") + "," + entry.sha1.toString("base64");
        lines.push(line);
    }
    
    fs.writeFileSync(this.filename, lines.join("\n"));
}


module.exports.logger = {
    info: console.info
    , error: console.error
}

