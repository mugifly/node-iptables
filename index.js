var spawn = require('child_process').spawn;
var lazy = require('lazy');

exports.allow = function (rule) {
    rule.target = 'ACCEPT';
    if (!rule.action) rule.action = '-A';
    newRule(rule);
};

exports.drop = function (rule) {
    rule.target = 'DROP';
    if (!rule.action) rule.action = '-A';
    newRule(rule);
};

exports.reject = function (rule) {
    rule.target = 'REJECT';
    if (!rule.action) rule.action = '-A';
    newRule(rule);
};

exports.policy = function(chain, target) {
    var rule = {
        chain: chain,
        action: '-P',
        target: target
    };

    newRule(rule);
};

exports.list = function(chain, cb) {
    var rule = {
        list : true,
        chain : chain,
        action : '-L',
        sudo : true
    };

    var cmd = iptables(rule);
    var result = '';
    cmd.stdout.on('data', function (data) {
        result += data.toString();
    })
    cmd.on('close', function (code) {
        var rules = [];
        var lines = result.split(/\n/);
        lines.forEach(function (line, i) {
            if (i <= 1 || line.match(/^\S*$/)) return;
            var fields = line.trim().split(/\s+/, 11);
            var parsed = {
                packets : fields[0],
                bytes : fields[1],
                target : fields[2],
                protocol : fields[3],
                opt : fields[4],
                in : fields[5],
                out : fields[6],
                src : fields[7],
                dst : fields[8],
                mac : fields[10]
            };
            rules.push(parsed);
        });
        cb(rules);
    });

};

exports.newRule = newRule;
exports.deleteRule = deleteRule;
exports.insertRule = insertRule;

function iptables (rule) {
    var args = iptablesArgs(rule);

    var cmd = 'iptables';
    if (rule.sudo) {
        cmd = 'sudo';
        args = ['iptables'].concat(args);
    }

    var proc = spawn(cmd, args);
    proc.stderr.on('data', function (buf) {
        console.error(buf.toString());
    });
    return proc;
}

function iptablesArgs (rule) {
    var args = [];

    if (!rule.chain) rule.chain = 'INPUT';

    if (rule.action === '-P') {
        args = args.concat([rule.action, rule.chain, rule.target]);
        return args;
    }

    if (rule.mac) args = args.concat(["-m", "mac","--mac-source", rule.mac]);
    if (rule.chain) args = args.concat([rule.action, rule.chain]);
    if (rule.protocol) args = args.concat(["-p", rule.protocol]);
    if (rule.src) args = args.concat(["--src", rule.src]);
    if (rule.dst) args = args.concat(["--dst", rule.dst]);
    if (rule.sport) args = args.concat(["--sport", rule.sport]);
    if (rule.dport) args = args.concat(["--dport", rule.dport]);
    if (rule.in) args = args.concat(["-i", rule.in]);
    if (rule.out) args = args.concat(["-o", rule.out]);
    if (rule.target) args = args.concat(["-j", rule.target]);
    if (rule.list) args = args.concat(["-n", "-v"]);
    if (rule.tcpFlags) args = args.concat(['-m', 'tcp', '--tcp-flags', rule.tcpFlags.mask, rule.tcpFlags.comp]);
    if (rule.state) args = args.concat(["-m", "state", "--state", rule.state]);

    return args;
}

function newRule (rule) {
    iptables(rule);
}

function deleteRule (rule) {
    rule.action = '-D';
    iptables(rule);
}

function insertRule (rule) {
    rule.action = '-I';
    iptables(rule);
}
