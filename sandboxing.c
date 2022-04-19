#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/signal.h>
#include <sys/user.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <libgen.h>
#include "sandbox.h"

#define _GNU_SOURCE

#define TRACE_OPTS (PTRACE_O_TRACEEXEC)

static void usage(const char *prog)
{
	fprintf(stderr, "usage: %s PROG [ARGS]\n", prog);
}

int main(int argc, char **argv)
{
	int pipefds[2];
	char data = '\0';
	pid_t child = 0;
	pid_t parent = getpid();

	if (argc < 2) {
		usage(basename(argv[0]));
		return EXIT_FAILURE;
	}

	if (pipe2(pipefds, O_CLOEXEC)) {
		perror("【Error】Failed to Setup Control Pipes");
		return EXIT_FAILURE;
	}

	child = fork();
	if (-1 == child) {
		perror("【Error】Failed to Build a Child Process");
		return EXIT_FAILURE;
	}

    /*进入父进程内*/
	if (child) {
		int status = 0;
		pid_t waitp;

		if (close(pipefds[1])) {
			perror("closing pipe end");
			return EXIT_FAILURE;
		}

		/* 把子进程设置为tracer*/
		if (prctl(PR_SET_PTRACER, child, 0, 0, 0) < 0) {
			if (errno != EINVAL) {
				perror("【Error】Unable to Set the Child Process as the tracer");
				return EXIT_FAILURE;
			}
		}

        //检测子进程是否成功创建
		if (read(pipefds[0], &data, 1) < 1) {
			fprintf(stderr, "【Error】Child Process Exited\n");
			return EXIT_FAILURE;
		}

        //使用了seccomp-BPF的程序，必须具有CAP_SYS_ADMIN权限；或者通过使用prctrl把no_new_priv设置bit位设置成1
		if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
			perror("【Error】Failed to Set No_new_privs Bit For the Parent");
			return EXIT_FAILURE;
		}

		setup_seccomp_filter();

        //execvp()函数接管当前的进程
		if (execvp(argv[1], &argv[1])) {
			fprintf(stderr, "【Error】Failed to Execute %s: %s\n",argv[1], strerror(errno));
			return EXIT_FAILURE;
		}

	}
    /*进入子进程*/
    else {
		int status = 0;
		pid_t waitp;

		if (close(pipefds[0])) {
			perror("closing pipe end");
			return EXIT_FAILURE;
		}

        //保证父进程退出时子进程也退出
		if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) < 0) {
			perror("【Erroe】Failed to Set Pdeathsig Bit for the Child Process");
			return EXIT_FAILURE;
		}

		/* 子进程作为tracer监控父进程 */
		if (ptrace(PTRACE_ATTACH, parent, NULL, NULL)) {
			perror("【Error】Failed to Attach to the Parent Process");
			return EXIT_FAILURE;
		}

        //waitpid()返回值小于0表示parent在调用中出现错误
		if ((waitp = waitpid(parent, &status, 0)) < 0) {
			perror("【Error】Waitpid Failed");
			return EXIT_FAILURE;
		}

		/* PTRACE_O_EXITKILL，当tracer退出时发送SIGKILL信号给tracee */
		if (ptrace(PTRACE_SETOPTIONS, parent, NULL, (TRACE_OPTS | PTRACE_O_SUSPEND_SECCOMP | PTRACE_O_EXITKILL))) {
			perror("【Error】Failed to Use Seccomp Filters for the Parent");
			return EXIT_FAILURE;
		}

		if (write(pipefds[1], &data, 1) < 1) {
			perror("【Error】Bad Write on Control Pipe");
			return EXIT_FAILURE;
		}

		while (waitp > 0) {
			if (-1 == waitp) {
				perror("【Error】Waitpid Failed");
				return EXIT_FAILURE;
			}

			/*status是waitpid()的返回值
			 * WIFEXITED(status)若进程正常退出则返回一个非0值
			 * 若上宏为真，此时可通过WEXITSTATUS(status)获取进程退出状态(exit时参数)*/
			if (WIFEXITED(status)) {
				fprintf(stderr, "Parent Exited with Code %d\n", WEXITSTATUS(status));
				return EXIT_SUCCESS;
			}

            /*WIFSIGNALED(status)若进程异常终止则返回一个非0值
             * 若上宏为真，此时可通过WTERMSIG(status)获取使得进程退出的信号编号 */
			if (WIFSIGNALED(status)) {
				fprintf(stderr, "Parent Was Kill by Signal %d\n", WTERMSIG(status));
				return EXIT_SUCCESS;
			}

            /*WIFSTOPPED(status)若进程处于暂停状态则返回一个非0值
             * 若上宏为真，此时可通过WSTOPSIG(status)获取使得进程暂停的信号编号 */
			if (WIFSTOPPED(status)) {
                /*在下一个exec()函数调用时停止子进程
                 * status >> 8是因为status有四个字节，但是前十六个字节未使用；返回值放在低十六位中的高八位*/

                /*获取寄存器的值*/
                int orig_rax;
                struct user_regs_struct regs;
                ptrace(PTRACE_GETREGS, parent, NULL ,&regs); // 获取被跟踪进程寄存器的值
                orig_rax = regs.orig_rax; // 获取rax寄存器的值
                printf("orig_rax: %d\n", orig_rax);

				if ((SIGTRAP | (PTRACE_EVENT_EXEC << 8)) == (status >> 8)) {
					/*将父进程内由data指向的值设定为ptrace选项，data作为位掩码来解释，由下面的标志指定*/
					if (ptrace(PTRACE_SETOPTIONS, parent, NULL, TRACE_OPTS)) {
						perror("【Error】Failed to Restart Seccomp Filters For the Parent Process");
						return EXIT_FAILURE;
					}
                    /*解除ATTACH操作*/
					if (ptrace(PTRACE_DETACH, parent, NULL, NULL)) {
						perror("【Error】Failed to Detach From the Parent Process");
						return EXIT_FAILURE;
					}
					return EXIT_SUCCESS;
				}
                /*parent进程继续往下执行*/
				if (ptrace(PTRACE_CONT, parent, NULL, NULL)) {
					perror("【Error】Failed to Resume the Parent Process");
					return EXIT_FAILURE;
				}
			} else {
				fprintf(stderr, "【ERROR】unexpected wait status %x，can locate the problem", status);
			}
			waitp = waitpid(parent, &status, 0);
		}
    }
	return EXIT_FAILURE;
}
