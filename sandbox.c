#define _GNU_SOURCE

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <seccomp.h>
#include <stdlib.h>
#include "sandbox.h"

#define SECCOMP_SYSCALL_ALLOW "Whitelist_mode"
#define SECCOMP_SYSCALL_DENY "Blacklist_mode"
#define SECCOMP_DEFAULT_ACTION "Log_mode"

//查看过最长的系统调用名长度不超20
#define SYSCALL_NAME_MAX_LEN 30

//添加系统调用函数
static void add_syscall(scmp_filter_ctx ctx, const char *syscall, uint32_t action)
{
	int syscall_nr = seccomp_syscall_resolve_name(syscall);
	if (__NR_SCMP_ERROR == syscall_nr) {
		fprintf(stderr, "【Error】Failed to find the syscall number for %s\n", syscall);
		seccomp_release(ctx);
		exit(1);
	}

	if (seccomp_rule_add_exact(ctx, action, syscall_nr, 0)) {
		fprintf(stderr, "【Error】Failed to add <%s> to the seccomp filter context\n", syscall);
		seccomp_release(ctx);
		exit(1);
	}
}

//获取操作名函数
static const char *get_seccomp_action_name(uint32_t action)
{
        const char *action_name;
        switch (action) {
            case SCMP_ACT_KILL_PROCESS:
                action_name = "KILL PROCESS";
                break;
            case SCMP_ACT_LOG:
                action_name = "ALLOW AND LOG";
                break;
            case SCMP_ACT_ALLOW:
                action_name = "ALLOW";
                break;
            default:
                /* 可扩展更多的过滤操作 */
                action_name = "Adding Later...";
        }
        return action_name;
}

void setup_seccomp_filter(void)
{
	scmp_filter_ctx seccomp_ctx;
	uint32_t seccomp_default_action = SCMP_ACT_KILL_PROCESS;
	uint32_t seccomp_syscall_action = SCMP_ACT_ALLOW;
	bool log_mode = false;
	char *cur = NULL;
	char syscall_name[SYSCALL_NAME_MAX_LEN] = {0};

	char *syscall_list = getenv(SECCOMP_DEFAULT_ACTION);
    //判断默认行为是否为log
	if (syscall_list) {
		log_mode = (0 == strncmp(syscall_list, "log", sizeof("log")));
	}

	syscall_list = getenv(SECCOMP_SYSCALL_ALLOW);
	if (syscall_list) {
        //【白名单模式】默认杀死或记录，特定的系统调用allow
		seccomp_default_action = log_mode ? SCMP_ACT_LOG : SCMP_ACT_KILL_PROCESS;
		seccomp_syscall_action = SCMP_ACT_ALLOW;
	} else if (syscall_list = getenv(SECCOMP_SYSCALL_DENY)) {
        //【黑名单模式】默认allow，特定的系统调用杀死或记录
		seccomp_default_action = SCMP_ACT_ALLOW;
		seccomp_syscall_action = log_mode ? SCMP_ACT_LOG : SCMP_ACT_KILL_PROCESS;
	} else
		return;

    //初始化默认的处理行为
	seccomp_ctx = seccomp_init(seccomp_default_action);
	if (NULL == seccomp_ctx) {
		fputs("【Error】Init Seccomp Rules Failed\n", stderr);
		exit(1);
	}
	fprintf(stderr, " Initializing Seccomp Rules......\n");

	cur = syscall_list;
	while (cur = strchrnul(syscall_list, (int)' ')) {
        //判断系统调用名长度是否合法
		if ((cur - syscall_list) > (SYSCALL_NAME_MAX_LEN - 1)) {
			fputs("【Error】Syscall Name is too long\n", stderr);
            fputs(" Pleas check and try again\n", stderr);
			seccomp_release(seccomp_ctx);
			exit(1);
		}

		memcpy(syscall_name, syscall_list, (cur - syscall_list));
		syscall_name[(cur - syscall_list)] = '\0';
		if (0 == strlen(syscall_name)) {
			if ('\0' == *cur)
				break;
			syscall_list = cur + 1;
			continue;
		}

		fprintf(stderr, "【Success】Adding <%s> to the Seccomp Filter [%s]\n", syscall_name, get_seccomp_action_name(seccomp_syscall_action));
		add_syscall(seccomp_ctx, syscall_name, seccomp_syscall_action);
		if ('\0' == *cur)
			break;
		else
			syscall_list = cur + 1;
	}

	/* 移除设置的环境变量*/
	if (unsetenv(SECCOMP_DEFAULT_ACTION)) {
		fputs("【Error】failed to unset SECCOMP_DEFAULT_ACTION\n", stderr);
		seccomp_release(seccomp_ctx);
		exit(1);
	}
	if (unsetenv(SECCOMP_SYSCALL_ALLOW)) {
		fputs("【Error】failed to unset SECCOMP_SYSCALL_ALLOW\n", stderr);
		seccomp_release(seccomp_ctx);
		exit(1);
	}
	if (unsetenv(SECCOMP_SYSCALL_DENY)) {
		fputs("【Error】failed to unset SECCOMP_SYSCALL_DENY\n", stderr);
		seccomp_release(seccomp_ctx);
		exit(1);
	}

	if (seccomp_load(seccomp_ctx)) {
		fputs("【Error】failed to load the seccomp filter\n", stderr);
		seccomp_release(seccomp_ctx);
		exit(1);
	}

    //程序执行完要释放规则
	seccomp_release(seccomp_ctx);
}
