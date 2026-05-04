#pragma once

#include <json-c/json.h>
#include <signal.h>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <string>
#include <unordered_map>

#include <arpa/inet.h>
#include <sys/ptrace.h>
#include <sys/user.h>

#include "process.hpp"
#include "config.hpp"
namespace rules
{

    // ---------------- ACTION ----------------

    enum class RuleAction
    {
        None,
        Log,
        Ask,  // 🔥 interactive
        Fail, // 🔥 auto block
        Kill
    };

    // ---------------- STORAGE ----------------

    inline std::unordered_map<std::string,
                              std::unordered_map<std::string, RuleAction>>
        file_rules;

    inline std::unordered_map<std::string,
                              std::unordered_map<std::string, RuleAction>>
        network_rules;

    inline std::unordered_map<std::string, RuleAction> syscall_rules;

    // ---------------- HELPERS ----------------

    inline RuleAction parse_action(const char *s)
    {
        if (!s)
            return RuleAction::None;

        if (strcmp(s, "log") == 0)
            return RuleAction::Log;
        if (strcmp(s, "ask") == 0)
            return RuleAction::Ask;
        if (strcmp(s, "fail") == 0)
            return RuleAction::Fail;
        if (strcmp(s, "kill") == 0)
            return RuleAction::Kill;

        return RuleAction::None;
    }

    inline const char *action_name(RuleAction a)
    {
        switch (a)
        {
        case RuleAction::Log:
            return "log";
        case RuleAction::Ask:
            return "ask";
        case RuleAction::Kill:
            return "kill";
        case RuleAction::Fail:
            return "fail";
        default:
            return "none";
        }
    }
    inline std::string extract_ip(const std::string &target)
    {
        size_t pos = target.find(':');
        if (pos == std::string::npos)
            return target;

        return target.substr(0, pos);
    }

    inline bool match_ipv4_cidr(const std::string &ip, const std::string &cidr)
    {
        // split "1.1.1.0/24"
        size_t slash = cidr.find('/');
        if (slash == std::string::npos)
            return false;

        std::string net = cidr.substr(0, slash);
        int prefix = std::stoi(cidr.substr(slash + 1));

        struct in_addr ip_addr{}, net_addr{};

        if (inet_pton(AF_INET, ip.c_str(), &ip_addr) != 1)
            return false;

        if (inet_pton(AF_INET, net.c_str(), &net_addr) != 1)
            return false;

        uint32_t ip_u = ntohl(ip_addr.s_addr);
        uint32_t net_u = ntohl(net_addr.s_addr);

        uint32_t mask = prefix == 0 ? 0 : (~0u << (32 - prefix));

        return (ip_u & mask) == (net_u & mask);
    }
    // ---------------- CORE: CANCEL SYSCALL ----------------

    inline void cancel_syscall(pid_t pid)
    {
#ifdef __x86_64__
        struct user_regs_struct regs;
#define PTRACE(req, ...) ptrace(static_cast<__ptrace_request>(req), __VA_ARGS__)
        if (PTRACE(PTRACE_GETREGS, pid, 0, &regs) == 0)
        {
            regs.orig_rax = -1;
            regs.rax = -EPERM; // ❌ prevent syscall execution
            PTRACE(PTRACE_SETREGS, pid, 0, &regs);
        }
#undef PTRACE
#endif
    }

    // ---------------- LOOKUPS ----------------

    inline RuleAction lookup_file_action(const std::string &path, const char *op)
    {
        // 1. exact match first
        auto it = file_rules.find(path);
        if (it != file_rules.end())
        {
            auto jt = it->second.find(op);
            if (jt != it->second.end())
                return jt->second;
        }

        // 2. wildcard match (prefix)
        for (const auto &kv : file_rules)
        {
            const std::string &rule_path = kv.first;

            // check if rule ends with '*'
            if (!rule_path.empty() && rule_path.back() == '*')
            {
                std::string prefix = rule_path.substr(0, rule_path.size() - 1);

                if (path.compare(0, prefix.size(), prefix) == 0)
                {
                    auto jt = kv.second.find(op);
                    if (jt != kv.second.end())
                        return jt->second;
                }
            }
        }

        return RuleAction::None;
    }

    inline RuleAction lookup_network_action(const std::string &target, const char *op)
{
    std::string ip = extract_ip(target);

    for (const auto &kv : network_rules)
    {
        const std::string &rule = kv.first;

        bool match = false;

        // CIDR match
        if (rule.find('/') != std::string::npos)
        {
            match = match_ipv4_cidr(ip, rule);
        }
        else
        {
            // exact IP match
            match = (ip == rule);
        }

        if (!match)
            continue;

        auto jt = kv.second.find(op);
        if (jt != kv.second.end())
            return jt->second;
    }

    return RuleAction::None;
}

    inline RuleAction lookup_syscall_action(const char *name)
    {
        auto it = syscall_rules.find(name);
        if (it == syscall_rules.end())
            return RuleAction::None;

        return it->second;
    }

    // ---------------- INTERACTIVE BLOCK ----------------

    inline bool prompt_block(pid_t pid,
                             const char *scope,
                             const char *op,
                             const std::string &target)
    {
        fprintf(stdout, "[RULE] block %s %s: %s\n", scope, op, target.c_str());
        fprintf(stdout, "    (r)esume / (f)ail ? ");
        fflush(stdout);

        std::string line;
        if (!std::getline(std::cin, line))
            return true; // default resume

        if (!line.empty() && (line[0] == 'f' || line[0] == 'F'))
        {
            cancel_syscall(pid); // 🔥 KEY CHANGE
            return false;
        }

        return true;
    }

    // ---------------- APPLY (FILE / NETWORK) ----------------

    inline bool handle_event_action(pid_t pid,
                                    const char *scope,
                                    const char *op,
                                    const std::string &target,
                                    RuleAction action)
    {
        switch (action)
        {
        case RuleAction::None:
            return true;

        case RuleAction::Log:
            LOG(0, "[RULE] log %s %s: %s\n", scope, op, target.c_str());
            return true;

        case RuleAction::Ask:
            return prompt_block(pid, scope, op, target);

        case RuleAction::Fail:
            LOG(0, "[RULE] fail %s %s: %s\n", scope, op, target.c_str());
            cancel_syscall(pid);
            return false;

        case RuleAction::Kill:
            LOG(0, "[RULE] kill %s %s: %s\n", scope, op, target.c_str());
            kill(get_tgid(pid), SIGKILL);
            return false;
        }

        return true;
    }

    inline bool apply_file_rule(pid_t pid,
                                const std::string &path,
                                const char *op)
    {
        return handle_event_action(pid,
                                   "file",
                                   op,
                                   path,
                                   lookup_file_action(path, op));
    }

    inline bool apply_network_rule(pid_t pid,
                                   const std::string &target,
                                   const char *op)
    {
        return handle_event_action(pid,
                                   "network",
                                   op,
                                   target,
                                   lookup_network_action(target, op));
    }

    // ---------------- APPLY (SYSCALL) ----------------

    inline bool apply_syscall_rule(pid_t pid, const char *name)
    {
        RuleAction action = lookup_syscall_action(name);

        switch (action)
        {
        case RuleAction::None:
            return true;

        case RuleAction::Log:
            LOG(0, "[RULE] log syscall: %s\n", name);
            return true;
        case RuleAction::Ask:
        {
            printf("[BLOCK] syscall: %s\n", name);
            printf("    (r)esume / (f)ail ? ");
            fflush(stdout);

            std::string line;
            if (!std::getline(std::cin, line))
                return true;

            if (!line.empty() && (line[0] == 'f' || line[0] == 'F'))
            {
                cancel_syscall(pid);
                return false;
            }

            return true;
        }

        case RuleAction::Fail:
            LOG(0, "[RULE] fail syscall: %s\n", name);
            cancel_syscall(pid);
            return false;
            {
                std::string line;
                if (!std::getline(std::cin, line))
                    return true;

                if (!line.empty() && (line[0] == 'f' || line[0] == 'F'))
                {
                    cancel_syscall(pid); // 🔥 KEY CHANGE
                    return false;
                }
            }

            return true;

        case RuleAction::Kill:
            LOG(0, "[RULE] kill syscall: %s\n", name);
            kill(get_tgid(pid), SIGKILL);
            return false;
        }

        return true;
    }

    // ---------------- LOAD JSON ----------------

    inline void load_rules(const std::string &path)
    {
        file_rules.clear();
        network_rules.clear();
        syscall_rules.clear();

        json_object *root = json_object_from_file(path.c_str());
        if (!root)
        {
            fprintf(stderr, "[rules] could not open %s\n", path.c_str());
            return;
        }

        // FILE RULES
        json_object *files_obj = nullptr;
        if (json_object_object_get_ex(root, "files", &files_obj))
        {
            json_object_object_foreach(files_obj, file_key, file_val)
            {
                if (!json_object_is_type(file_val, json_type_object))
                    continue;

                std::unordered_map<std::string, RuleAction> ops;

                json_object_object_foreach(file_val, op_key, action_val)
                {
                    if (json_object_is_type(action_val, json_type_string))
                    {
                        ops[op_key] =
                            parse_action(json_object_get_string(action_val));
                    }
                }

                file_rules[file_key] = std::move(ops);
            }
        }

        // NETWORK RULES
        json_object *network_obj = nullptr;
        if (json_object_object_get_ex(root, "network", &network_obj))
        {
            json_object_object_foreach(network_obj, net_key, net_val)
            {
                if (!json_object_is_type(net_val, json_type_object))
                    continue;

                std::unordered_map<std::string, RuleAction> ops;

                json_object_object_foreach(net_val, op_key, action_val)
                {
                    if (json_object_is_type(action_val, json_type_string))
                    {
                        ops[op_key] =
                            parse_action(json_object_get_string(action_val));
                    }
                }

                network_rules[net_key] = std::move(ops);
            }
        }

        // SYSCALL RULES
        json_object *syscalls_obj = nullptr;
        if (json_object_object_get_ex(root, "syscalls", &syscalls_obj))
        {
            json_object_object_foreach(syscalls_obj, sc_key, sc_val)
            {
                if (json_object_is_type(sc_val, json_type_string))
                {
                    syscall_rules[sc_key] =
                        parse_action(json_object_get_string(sc_val));
                }
            }
        }

        json_object_put(root);
    }

} // namespace rules