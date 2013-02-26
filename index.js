var exec = require('child_process').exec;
var lazy = require('lazy');

exports.allow = function (rule, callback) {
    rule.target = 'ACCEPT';
    if (!rule.action) rule.action = '-A';
    newRule(rule, callback);
};

exports.drop = function (rule, callback) {
    rule.target = 'DROP';
    if (!rule.action) rule.action = '-A';
    newRule(rule, callback);
};

exports.reject = function (rule, callback) {
    rule.target = 'REJECT';
    if (!rule.action) rule.action = '-A';
    newRule(rule, callback);
};

exports.policy = function(chain, target, callback) {
    var rule = {
        chain: chain,
        action: '-P',
        target: target
    };

    newRule(rule, callback);
};

exports.list = function(chain, callback) {
    var rule = {
        list : true,
        chain : chain,
        action : '-L',
        sudo : true
    };

    iptables(rule, function(err, output) {
        if (err) {
            callback(err);
            return;
        }

        lazy(output.stdout)
            .lines
            .map(String)
            .skip(2)
            .map(function(line) {
                // packets, bytes, target, pro, opt, in, out, src, dst, opts
                var fields = line.trim().split(/\s+/, 9);
                return {
                    parsed: {
                        packets: fields[0],
                        bytes: fields[1],
                        target: fields[2],
                        protocol: fields[3],
                        opt: fields[4],
                        in: fields[5],
                        out: fields[6],
                        src: fields[7],
                        dst: fields[8]
                    },
                    raw: line.trim()
                };

            })
            .join(function(rules) {
                callback(err, rules);
            });
    });
};

exports.newRule = newRule;
exports.deleteRule = deleteRule;

function iptables(rule, callback) {
    var args = iptablesArgs(rule);

    var cmd = ['iptables'].concat(args);
    if (rule.sudo) {
        cmd = ['sudo'].concat(cmd);
    }

    exec(cmd.join(' '), function(err, stdout, stderr) {
        callback(err, {
            stdout: stdout.toString(),
            stderr: stderr.toString()
        });
    });
}

function iptablesArgs (rule) {
    var args = [];

    if (!rule.chain) rule.chain = 'INPUT';

    if (rule.action === '-P') {
        args = args.concat([rule.action, rule.chain, rule.target]);
        return args;
    }

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

function newRule (rule, callback) {
    iptables(rule, callback);
}

function deleteRule (rule, callback) {
    rule.action = '-D';
    iptables(rule, callback);
}

