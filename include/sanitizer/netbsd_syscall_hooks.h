//===-- netbsd_syscall_hooks.h --------------------------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file is a part of public sanitizer interface.
//
// System call handlers.
//
// Interface methods declared in this header implement pre- and post- syscall
// actions for the active sanitizer.
// Usage:
//   __sanitizer_syscall_pre_getfoo(...args...);
//   long res = syscall(SYS_getfoo, ...args...);
//   __sanitizer_syscall_post_getfoo(res, ...args...);
//
// DO NOT EDIT! THIS FILE HAS BEEN AUTOMATICALLY GENERATED
//
//===----------------------------------------------------------------------===//
#ifndef SANITIZER_NETBSD_SYSCALL_HOOKS_H
#define SANITIZER_NETBSD_SYSCALL_HOOKS_H

a kuku

    0 INDIR { int|sys||syscall(int code, \
a kuku

1	STD 		{
    void | sys || exit(int rval); }
a kuku

2	STD 		{
    int | sys || fork(void); }
a kuku

3	STD 	 RUMP	{
    ssize_t | sys || read(int fd, void *buf, size_t nbyte); }
a kuku

4	STD 	 RUMP	{ ssize_t|sys||write(int fd, const void *buf, \
a kuku

5	STD 	 RUMP	{ int|sys||open(const char *path, \
a kuku

6	STD	 RUMP	{
        int | sys || close(int fd); }
a kuku

7	COMPAT_50 MODULAR compat { int|sys||wait4(pid_t pid, int *status, \
a kuku

8	COMPAT_43 MODULAR compat	\
a kuku

9	STD 	 RUMP	{
          int | sys || link(const char *path, const char *link); }
a kuku

10	STD 	 RUMP	{
          int | sys || unlink(const char *path); }
a kuku

11	OBSOL		execv
a kuku

12	STD 	 RUMP	{
          int | sys || chdir(const char *path); }
a kuku

13	STD 	 RUMP	{
          int | sys || fchdir(int fd); }
a kuku

14	COMPAT_50 MODULAR compat RUMP	\
a kuku

15	STD 	 RUMP	{
          int | sys || chmod(const char *path, mode_t mode); }
a kuku

16	STD 	 RUMP	{ int|sys||chown(const char *path, uid_t uid, \
a kuku

17	STD 		{
            int | sys || obreak(char *nsize); } break
a kuku

18	COMPAT_20 MODULAR compat { int|sys||getfsstat(struct statfs12 *buf, \
a kuku

19	COMPAT_43 MODULAR compat	\
a kuku

20	NOERR 	RUMP	{
              pid_t | sys || getpid_with_ppid(void); } getpid
a kuku

21	COMPAT_40 MODULAR compat	\
a kuku

22	STD 	RUMP	{
              int | sys || unmount(const char *path, int flags); }
a kuku

23	STD 	RUMP	{
              int | sys || setuid(uid_t uid); }
a kuku

24	NOERR 	RUMP	{
              uid_t | sys || getuid_with_euid(void); } getuid
a kuku

25	NOERR 	RUMP	{
              uid_t | sys || geteuid(void); }
a kuku

26	STD 	MODULAR ptrace	\
a kuku

27	STD 	RUMP	{ ssize_t|sys||recvmsg(int s, struct msghdr *msg, \
a kuku

28	STD 	RUMP	{ ssize_t|sys||sendmsg(int s, \
a kuku

29	STD 	RUMP	{ ssize_t|sys||recvfrom(int s, void *buf, size_t len, \
a kuku

30	STD	RUMP	{ int|sys||accept(int s, struct sockaddr *name, \
a kuku

31	STD	RUMP	{ int|sys||getpeername(int fdes, struct sockaddr *asa, \
a kuku

32	STD	RUMP	{ int|sys||getsockname(int fdes, struct sockaddr *asa, \
a kuku

33	STD 	RUMP	{
                          int | sys || access(const char *path, int flags); }
a kuku

34	STD 	 RUMP	{
                          int | sys || chflags(const char *path, u_long flags); }
a kuku

35	STD 	RUMP	{
                          int | sys || fchflags(int fd, u_long flags); }
a kuku

36	NOERR 	 RUMP	{
                          void | sys || sync(void); }
a kuku

37	STD 		{
                          int | sys || kill(pid_t pid, int signum); }
a kuku

38	COMPAT_43 MODULAR compat	\
a kuku

39	NOERR 	RUMP	{
                          pid_t | sys || getppid(void); }
a kuku

40	COMPAT_43 MODULAR compat	\
a kuku

41	STD 	RUMP	{
                          int | sys || dup(int fd); }
a kuku

42	STD 	RUMP	{
                          int | sys || pipe(void); }
a kuku

43	NOERR 	RUMP	{
                          gid_t | sys || getegid(void); }
a kuku

44	STD 		{ int|sys||profil(char *samples, size_t size, \
a kuku

45	STD 	RUMP	{ int|sys||ktrace(const char *fname, int ops, \
a kuku

46	COMPAT_13 MODULAR compat { int|sys||sigaction(int signum, \
a kuku

47	NOERR 	RUMP	{
                                gid_t | sys || getgid_with_egid(void); } getgid
a kuku

48	COMPAT_13 MODULAR compat { int|sys||sigprocmask(int how, \
a kuku

49	STD 	RUMP	{
                                  int | sys ||
                                      __getlogin(char *namebuf, size_t namelen); }
a kuku

50	STD 	RUMP 	{
                                  int | sys || __setlogin(const char *namebuf); }
a kuku

51	STD 		{
                                  int | sys || acct(const char *path); }
a kuku

52	COMPAT_13 MODULAR compat {
                                  int | sys || sigpending(void); } sigpending13
a kuku

53	COMPAT_13 MODULAR compat { int|sys||sigaltstack( \
a kuku

54	STD	RUMP	{ int|sys||ioctl(int fd, \
a kuku

55	COMPAT_12 MODULAR compat {
                                      int | sys || reboot(int opt); } oreboot
a kuku

56	STD 	 RUMP	{
                                      int | sys || revoke(const char *path); }
a kuku

57	STD 	 RUMP	{ int|sys||symlink(const char *path, \
a kuku

58	STD 	 RUMP	{ ssize_t|sys||readlink(const char *path, char *buf, \
a kuku

59	STD 		{ int|sys||execve(const char *path, \
a kuku

60	STD 	 RUMP	{
                                            mode_t | sys ||
                                                umask(mode_t newmask); }
a kuku

61	STD 	 RUMP	{
                                            int | sys ||
                                                chroot(const char *path); }
a kuku

62	COMPAT_43 MODULAR compat	\
a kuku

63	COMPAT_43 MODULAR compat	\
a kuku

64	COMPAT_43 MODULAR compat	\
a kuku

65	COMPAT_12 MODULAR compat {
                                            int | sys ||
                                                msync(void *addr, size_t len); }
a kuku

66	STD 		{
                                            int | sys || vfork(void); }
a kuku

67	OBSOL		vread
a kuku

68	OBSOL		vwrite
a kuku

69	STD 		{
                                            int | sys || sbrk(intptr_t incr); }
a kuku

70	STD 		{
                                            int | sys || sstk(int incr); }
a kuku

71	COMPAT_43 MODULAR compat	\
a kuku

72	STD 		{
                                            int | sys || ovadvise(int anom); } vadvise
a kuku

73	STD 		{
                                            int | sys ||
                                                munmap(void *addr, size_t len); }
a kuku

74	STD 		{ int|sys||mprotect(void *addr, size_t len, \
a kuku

75	STD 		{ int|sys||madvise(void *addr, size_t len, \
a kuku

76	OBSOL		vhangup
a kuku

77	OBSOL		vlimit
a kuku

78	STD 		{ int|sys||mincore(void *addr, size_t len, \
a kuku

79	STD 	RUMP	{ int|sys||getgroups(int gidsetsize, \
a kuku

80	STD 	RUMP	{ int|sys||setgroups(int gidsetsize, \
a kuku

81	STD 	RUMP	{
                                                      int | sys ||
                                                          getpgrp(void); }
a kuku

82	STD 	RUMP	{
                                                      int | sys ||
                                                          setpgid(pid_t pid,
                                                                  pid_t pgid); }
a kuku

83	COMPAT_50 MODULAR compat { int|sys||setitimer(int which, \
a kuku

84	COMPAT_43 MODULAR compat {
                                                        int | sys || wait(void); } owait
a kuku

85	COMPAT_12 MODULAR compat {
                                                        int | sys ||
                                                            swapon(const char
                                                                       *name); } oswapon
a kuku

86	COMPAT_50 MODULAR compat { int|sys||getitimer(int which, \
a kuku

87	COMPAT_43 MODULAR compat	\
a kuku

88	COMPAT_43 MODULAR compat	\
a kuku

89	COMPAT_43 MODULAR compat	\
a kuku

90	STD 	 RUMP	{
                                                          int | sys ||
                                                              dup2(int from,
                                                                   int to); }
a kuku

91	UNIMPL		getdopt
a kuku

92	STD	RUMP	{
                                                          int | sys ||
                                                              fcntl(int fd,
                                                                    int cmd,
                                                                    ... void
                                                                        *arg); }
a kuku

93	COMPAT_50 MODULAR compat RUMP	\
a kuku

94	UNIMPL		setdopt
a kuku

95	STD	RUMP 	{
                                                          int | sys ||
                                                              fsync(int fd); }
a kuku

96	STD 		{
                                                          int | sys ||
                                                              setpriority(
                                                                  int which,
                                                                  id_t who,
                                                                  int prio); }
a kuku

97	COMPAT_30 MODULAR compat	\
a kuku

98	STD	RUMP	{ int|sys||connect(int s, const struct sockaddr *name, \
a kuku

99	COMPAT_43 MODULAR compat	\
a kuku

100	STD 		{
                                                            int | sys ||
                                                                getpriority(
                                                                    int which,
                                                                    id_t who); }
a kuku

101	COMPAT_43 MODULAR compat { int|sys||send(int s, void *buf, int len, \
a kuku

102	COMPAT_43 MODULAR compat { int|sys||recv(int s, void *buf, int len, \
a kuku

103	COMPAT_13 MODULAR compat	\
a kuku

104	STD	RUMP	{ int|sys||bind(int s, const struct sockaddr *name, \
a kuku

105	STD	RUMP	{ int|sys||setsockopt(int s, int level, int name, \
a kuku

106	STD	RUMP	{
                                                                    int | sys ||
                                                                        listen(
                                                                            int s,
                                                                            int backlog); }
a kuku

107	OBSOL		vtimes
a kuku

108	COMPAT_43 MODULAR compat	\
a kuku

109	COMPAT_43 MODULAR compat {
                                                                    int | sys ||
                                                                        sigblock(
                                                                            int mask); } osigblock
a kuku

110	COMPAT_43 MODULAR compat {
                                                                    int | sys ||
                                                                        sigsetmask(
                                                                            int mask); } osigsetmask
a kuku

111	COMPAT_13 MODULAR compat {
                                                                    int | sys ||
                                                                        sigsuspend(
                                                                            int mask); } sigsuspend13
a kuku

112	COMPAT_43 MODULAR compat { int|sys||sigstack(struct sigstack *nss, \
a kuku

113	COMPAT_43 MODULAR compat	\
a kuku

114	COMPAT_43 MODULAR compat	\
a kuku

115	OBSOL		vtrace
a kuku

116	COMPAT_50 MODULAR compat { int|sys||gettimeofday(struct timeval50 *tp, \
a kuku

117	COMPAT_50 MODULAR compat	\
a kuku

118	STD	RUMP	{ int|sys||getsockopt(int s, int level, int name, \
a kuku

119	OBSOL		resuba
a kuku

120	STD 	RUMP	{ ssize_t|sys||readv(int fd, \
a kuku

121	STD 	RUMP	{ ssize_t|sys||writev(int fd, \
a kuku

122	COMPAT_50 MODULAR compat	\
a kuku

123	STD 	 RUMP	{
                                                                              int | sys ||
                                                                                  fchown(
                                                                                      int fd,
                                                                                      uid_t
                                                                                          uid,
                                                                                      gid_t
                                                                                          gid); }
a kuku

124	STD 	 RUMP	{
                                                                              int | sys ||
                                                                                  fchmod(
                                                                                      int fd,
                                                                                      mode_t
                                                                                          mode); }
a kuku

125	COMPAT_43 MODULAR compat	\
a kuku

126	STD 	RUMP	{
                                                                              int | sys ||
                                                                                  setreuid(
                                                                                      uid_t
                                                                                          ruid,
                                                                                      uid_t
                                                                                          euid); }
a kuku

127	STD 	RUMP	{
                                                                              int | sys ||
                                                                                  setregid(
                                                                                      gid_t
                                                                                          rgid,
                                                                                      gid_t
                                                                                          egid); }
a kuku

128	STD 	 RUMP	{
                                                                              int | sys ||
                                                                                  rename(
                                                                                      const char
                                                                                          *from,
                                                                                      const char
                                                                                          *to); }
a kuku

129	COMPAT_43 MODULAR compat	\
a kuku

130	COMPAT_43 MODULAR compat	\
a kuku

131	STD 	 RUMP	{
                                                                              int | sys ||
                                                                                  flock(
                                                                                      int fd,
                                                                                      int how); }
a kuku

132	STD 	 RUMP	{
                                                                              int | sys ||
                                                                                  mkfifo(
                                                                                      const char
                                                                                          *path,
                                                                                      mode_t
                                                                                          mode); }
a kuku

133	STD 	 RUMP	{ ssize_t|sys||sendto(int s, const void *buf, \
a kuku

134	STD	 RUMP	{
                                                                                int | sys ||
                                                                                    shutdown(
                                                                                        int s,
                                                                                        int how); }
a kuku

135	STD	 RUMP	{ int|sys||socketpair(int domain, int type, \
a kuku

136	STD 	 RUMP	{
                                                                                  int | sys ||
                                                                                      mkdir(
                                                                                          const char
                                                                                              *path,
                                                                                          mode_t
                                                                                              mode); }
a kuku

137	STD 	 RUMP	{
                                                                                  int | sys ||
                                                                                      rmdir(
                                                                                          const char
                                                                                              *path); }
a kuku

138	COMPAT_50 MODULAR compat RUMP { int|sys||utimes(const char *path, \
a kuku

139	OBSOL		4.2 sigreturn
a kuku

140	COMPAT_50 MODULAR compat	\
a kuku

141	COMPAT_43 MODULAR compat	\
a kuku

142	COMPAT_43 MODULAR compat	\
a kuku

143	COMPAT_43 MODULAR compat	\
a kuku

144	COMPAT_43 MODULAR compat	\
a kuku

145	COMPAT_43 MODULAR compat { int|sys||setrlimit(int which, \
a kuku

146	COMPAT_43 MODULAR compat	\
a kuku

147	STD 	RUMP 	{
                                                                                      int | sys ||
                                                                                          setsid(
                                                                                              void); }
a kuku

148	COMPAT_50 MODULAR XXX { int|sys||quotactl(const char *path, int cmd, \
a kuku

149	COMPAT_43 MODULAR compat {
                                                                                        int | sys ||
                                                                                            quota(
                                                                                                void); } oquota
a kuku

150	COMPAT_43 MODULAR compat { int|sys||getsockname(int fdec, void *asa, \
a kuku

151	UNIMPL
a kuku

152	UNIMPL
a kuku

153	UNIMPL
a kuku

154	UNIMPL
a kuku

155	STD MODULAR nfsserver RUMP  {
                                                                                          int | sys ||
                                                                                              nfssvc(
                                                                                                  int flag,
                                                                                                  void *
                                                                                                      argp); }
a kuku

156	COMPAT_43 MODULAR compat	\
a kuku

157	COMPAT_20 MODULAR compat { int|sys||statfs(const char *path, \
a kuku

158	COMPAT_20 MODULAR compat	\
a kuku

159	UNIMPL
a kuku

160	UNIMPL
a kuku

161	COMPAT_30 MODULAR compat { int|sys||getfh(const char *fname, \
a kuku

162	COMPAT_09 MODULAR compat	\
a kuku

163	COMPAT_09 MODULAR compat	\
a kuku

164	COMPAT_09 MODULAR compat	\
a kuku

165	STD 		{
                                                                                              int | sys ||
                                                                                                  sysarch(
                                                                                                      int op,
                                                                                                      void *
                                                                                                          parms); }
a kuku

166	UNIMPL
a kuku

167	UNIMPL
a kuku

168	UNIMPL
#if !defined(_LP64)
a kuku

169	COMPAT_10 MODULAR sysv_ipc	\
#else
a kuku

169	EXCL		1.0 semsys
#endif
#if !defined(_LP64)
a kuku

170	COMPAT_10 MODULAR sysv_ipc	\
#else
a kuku

170	EXCL		1.0 msgsys
#endif
#if !defined(_LP64)
a kuku

171	COMPAT_10 MODULAR sysv_ipc	\
#else
a kuku

171	EXCL		1.0 shmsys
#endif
a kuku

172	UNIMPL
a kuku

173	STD 	 RUMP	{ ssize_t|sys||pread(int fd, void *buf, \
a kuku

174	STD 	 RUMP	{ ssize_t|sys||pwrite(int fd, const void *buf, \
a kuku

175	COMPAT_30	{
                                                                                                  int | sys ||
                                                                                                      ntp_gettime(
                                                                                                          struct
                                                                                                          ntptimeval30 *
                                                                                                          ntvp); }
#if defined(NTP) || !defined(_KERNEL_OPT)
a kuku

176	STD 		{
                                                                                                  int | sys ||
                                                                                                      ntp_adjtime(
                                                                                                          struct
                                                                                                          timex *
                                                                                                          tp); }
#else
a kuku

176	EXCL		ntp_adjtime
#endif
a kuku

177	UNIMPL
a kuku

178	UNIMPL
a kuku

179	UNIMPL
a kuku

180	UNIMPL
a kuku

181	STD 	RUMP	{
                                                                                                  int | sys ||
                                                                                                      setgid(
                                                                                                          gid_t
                                                                                                              gid); }
a kuku

182	STD 	RUMP	{
                                                                                                  int | sys ||
                                                                                                      setegid(
                                                                                                          gid_t
                                                                                                              egid); }
a kuku

183	STD 	RUMP	{
                                                                                                  int | sys ||
                                                                                                      seteuid(
                                                                                                          uid_t
                                                                                                              euid); }
a kuku

184	STD MODULAR lfs	{ int|sys||lfs_bmapv(fsid_t *fsidp, \
a kuku

185	STD MODULAR lfs	{ int|sys||lfs_markv(fsid_t *fsidp, \
a kuku

186	STD MODULAR lfs	{
                                                                                                      int | sys ||
                                                                                                          lfs_segclean(
                                                                                                              fsid_t *
                                                                                                                  fsidp,
                                                                                                              u_long
                                                                                                                  segment); }
a kuku

187	COMPAT_50 MODULAR compat { int|sys||lfs_segwait(fsid_t *fsidp, \
a kuku

188	COMPAT_12 MODULAR compat	\
a kuku

189	COMPAT_12 MODULAR compat	\
a kuku

190	COMPAT_12 MODULAR compat { int|sys||lstat(const char *path, \
a kuku

191	STD 	RUMP	{
                                                                                                          long | sys ||
                                                                                                              pathconf(
                                                                                                                  const char
                                                                                                                      *path,
                                                                                                                  int name); }
a kuku

192	STD 	RUMP	{
                                                                                                          long | sys ||
                                                                                                              fpathconf(
                                                                                                                  int fd,
                                                                                                                  int name); }
a kuku

193	UNIMPL
a kuku

194	STD 	RUMP	{ int|sys||getrlimit(int which, \
a kuku

195	STD 	RUMP	{ int|sys||setrlimit(int which, \
a kuku

196	COMPAT_12 MODULAR compat	\
a kuku

197	STD 		{ void *|sys||mmap(void *addr, size_t len, int prot, \
a kuku

198	INDIR		{ quad_t|sys||__syscall(quad_t code, \
a kuku

199	STD 	 RUMP	{ off_t|sys||lseek(int fd, int PAD, off_t offset, \
a kuku

200	STD 	 RUMP	{ int|sys||truncate(const char *path, int PAD, \
a kuku

201	STD 	 RUMP	{
                                                                                                                      int | sys ||
                                                                                                                          ftruncate(
                                                                                                                              int fd,
                                                                                                                              int PAD,
                                                                                                                              off_t
                                                                                                                                  length); }
a kuku

202	STD	 RUMP 	{ int|sys||__sysctl(const int *name, u_int namelen, \
a kuku

203	STD 		{
                                                                                                                        int | sys ||
                                                                                                                            mlock(
                                                                                                                                const void
                                                                                                                                    *addr,
                                                                                                                                size_t
                                                                                                                                    len); }
a kuku

204	STD 		{
                                                                                                                        int | sys ||
                                                                                                                            munlock(
                                                                                                                                const void
                                                                                                                                    *addr,
                                                                                                                                size_t
                                                                                                                                    len); }
a kuku

205	STD 		{
                                                                                                                        int | sys ||
                                                                                                                            undelete(
                                                                                                                                const char
                                                                                                                                    *path); }
a kuku

206	COMPAT_50 MODULAR compat RUMP { int|sys||futimes(int fd, \
a kuku

207	STD 	 RUMP	{
                                                                                                                          pid_t | sys ||
                                                                                                                              getpgid(
                                                                                                                                  pid_t
                                                                                                                                      pid); }
a kuku

208	STD	 RUMP	{
                                                                                                                          int | sys ||
                                                                                                                              reboot(
                                                                                                                                  int opt,
                                                                                                                                  char *
                                                                                                                                      bootstr); }
a kuku

209	STD 	 RUMP	{ int|sys||poll(struct pollfd *fds, u_int nfds, \
a kuku

210	EXTERN	MODULAR openafs { int|sys||afssys(long id, long a1, long a2, \
a kuku

211	UNIMPL
a kuku

212	UNIMPL
a kuku

213	UNIMPL
a kuku

214	UNIMPL
a kuku

215	UNIMPL
a kuku

216	UNIMPL
a kuku

217	UNIMPL
a kuku

218	UNIMPL
a kuku

219	UNIMPL
a kuku

220	COMPAT_14 MODULAR sysv_ipc	\
a kuku

221	STD MODULAR sysv_ipc { int|sys||semget(key_t key, int nsems, \
a kuku

222	STD MODULAR sysv_ipc { int|sys||semop(int semid, struct sembuf *sops, \
a kuku

223	STD MODULAR sysv_ipc {
                                                                                                                                  int | sys ||
                                                                                                                                      semconfig(
                                                                                                                                          int flag); }
a kuku

224	COMPAT_14 MODULAR sysv_ipc { int|sys||msgctl(int msqid, int cmd, \
a kuku

225	STD MODULAR sysv_ipc {
                                                                                                                                    int | sys ||
                                                                                                                                        msgget(
                                                                                                                                            key_t
                                                                                                                                                key,
                                                                                                                                            int msgflg); }
a kuku

226	STD MODULAR sysv_ipc { int|sys||msgsnd(int msqid, const void *msgp, \
a kuku

227	STD MODULAR sysv_ipc { ssize_t|sys||msgrcv(int msqid, void *msgp, \
a kuku

228	STD MODULAR sysv_ipc { void *|sys||shmat(int shmid,	\
a kuku

229	COMPAT_14 MODULAR sysv_ipc { int|sys||shmctl(int shmid, int cmd, \
a kuku

230	STD MODULAR sysv_ipc {
                                                                                                                                            int | sys ||
                                                                                                                                                shmdt(
                                                                                                                                                    const void
                                                                                                                                                        *shmaddr); }
a kuku

231	STD MODULAR sysv_ipc { int|sys||shmget(key_t key, size_t size,	\
a kuku

232	COMPAT_50 MODULAR compat { int|sys||clock_gettime(clockid_t clock_id, \
a kuku

233	COMPAT_50 MODULAR compat { int|sys||clock_settime(clockid_t clock_id, \
a kuku

234	COMPAT_50 MODULAR compat { int|sys||clock_getres(clockid_t clock_id, \
a kuku

235	STD  RUMP	{ int|sys||timer_create(clockid_t clock_id, \
a kuku

236	STD  RUMP	{
                                                                                                                                                      int | sys ||
                                                                                                                                                          timer_delete(
                                                                                                                                                              timer_t
                                                                                                                                                                  timerid); }
a kuku

237	COMPAT_50 MODULAR compat { int|sys||timer_settime(timer_t timerid, \
a kuku

238	COMPAT_50 MODULAR compat { int|sys||timer_gettime(timer_t timerid, \
a kuku

239	STD  RUMP	{
                                                                                                                                                          int | sys ||
                                                                                                                                                              timer_getoverrun(
                                                                                                                                                                  timer_t
                                                                                                                                                                      timerid); }
a kuku

240	COMPAT_50 MODULAR compat	\
a kuku

241	STD 	 RUMP	{
                                                                                                                                                          int | sys ||
                                                                                                                                                              fdatasync(
                                                                                                                                                                  int fd); }
a kuku

242	STD 		{
                                                                                                                                                          int | sys ||
                                                                                                                                                              mlockall(
                                                                                                                                                                  int flags); }
a kuku

243	STD 		{
                                                                                                                                                          int | sys ||
                                                                                                                                                              munlockall(
                                                                                                                                                                  void); }
a kuku

244	COMPAT_50 MODULAR compat	\
a kuku

245	STD		{ int|sys||sigqueueinfo(pid_t pid, \
a kuku

246	STD RUMP 	{
                                                                                                                                                            int | sys ||
                                                                                                                                                                modctl(
                                                                                                                                                                    int cmd,
                                                                                                                                                                    void *
                                                                                                                                                                        arg); }
a kuku

247	STD MODULAR ksem RUMP {
                                                                                                                                                            int | sys ||
                                                                                                                                                                _ksem_init(
                                                                                                                                                                    unsigned int
                                                                                                                                                                        value,
                                                                                                                                                                    intptr_t
                                                                                                                                                                        *idp); }
a kuku

248	STD MODULAR ksem RUMP { int|sys||_ksem_open(const char *name, int oflag, \
a kuku

249	STD MODULAR ksem RUMP {
                                                                                                                                                              int | sys ||
                                                                                                                                                                  _ksem_unlink(
                                                                                                                                                                      const char
                                                                                                                                                                          *name); }
a kuku

250	STD MODULAR ksem RUMP {
                                                                                                                                                              int | sys ||
                                                                                                                                                                  _ksem_close(
                                                                                                                                                                      intptr_t
                                                                                                                                                                          id); }
a kuku

251	STD MODULAR ksem RUMP {
                                                                                                                                                              int | sys ||
                                                                                                                                                                  _ksem_post(
                                                                                                                                                                      intptr_t
                                                                                                                                                                          id); }
a kuku

252	STD MODULAR ksem RUMP {
                                                                                                                                                              int | sys ||
                                                                                                                                                                  _ksem_wait(
                                                                                                                                                                      intptr_t
                                                                                                                                                                          id); }
a kuku

253	STD MODULAR ksem RUMP {
                                                                                                                                                              int | sys ||
                                                                                                                                                                  _ksem_trywait(
                                                                                                                                                                      intptr_t
                                                                                                                                                                          id); }
a kuku

254	STD MODULAR ksem RUMP { int|sys||_ksem_getvalue(intptr_t id, \
a kuku

255	STD MODULAR ksem RUMP {
                                                                                                                                                                int | sys ||
                                                                                                                                                                    _ksem_destroy(
                                                                                                                                                                        intptr_t
                                                                                                                                                                            id); }
a kuku

256	STD MODULAR ksem RUMP { int|sys||_ksem_timedwait(intptr_t id, \
a kuku

257	STD MODULAR mqueue	\
a kuku

258	STD MODULAR mqueue	{
                                                                                                                                                                  int | sys ||
                                                                                                                                                                      mq_close(
                                                                                                                                                                          mqd_t
                                                                                                                                                                              mqdes); }
a kuku

259	STD MODULAR mqueue	{
                                                                                                                                                                  int | sys ||
                                                                                                                                                                      mq_unlink(
                                                                                                                                                                          const char
                                                                                                                                                                              *name); }
a kuku

260	STD MODULAR mqueue	\
a kuku

261	STD MODULAR mqueue	\
a kuku

262	STD MODULAR mqueue	\
a kuku

263	STD MODULAR mqueue	\
a kuku

264	STD MODULAR mqueue	\
a kuku

265	COMPAT_50 MODULAR compat	\
a kuku

266	COMPAT_50 MODULAR compat	\
a kuku

267	UNIMPL
a kuku

268	UNIMPL
a kuku

269	UNIMPL
a kuku

270	STD 	 RUMP	{ int|sys||__posix_rename(const char *from, \
a kuku

271	STD 		{
                                                                                                                                                                    int | sys ||
                                                                                                                                                                        swapctl(
                                                                                                                                                                            int cmd,
                                                                                                                                                                            void *
                                                                                                                                                                                arg,
                                                                                                                                                                            int misc); }
a kuku

272	COMPAT_30 MODULAR compat {
                                                                                                                                                                    int | sys ||
                                                                                                                                                                        getdents(
                                                                                                                                                                            int fd,
                                                                                                                                                                            char *
                                                                                                                                                                                buf,
                                                                                                                                                                            size_t
                                                                                                                                                                                count); }
a kuku

273	STD 		{ int|sys||minherit(void *addr, size_t len, \
a kuku

274	STD 	 RUMP	{
                                                                                                                                                                      int | sys ||
                                                                                                                                                                          lchmod(
                                                                                                                                                                              const char
                                                                                                                                                                                  *path,
                                                                                                                                                                              mode_t
                                                                                                                                                                                  mode); }
a kuku

275	STD 	 RUMP	{ int|sys||lchown(const char *path, uid_t uid, \
a kuku

276	COMPAT_50 MODULAR compat RUMP { int|sys||lutimes(const char *path, \
a kuku

277	STD 		{
                                                                                                                                                                          int |
                                                                                                                                                                              sys |
                                                                                                                                                                              13 |
                                                                                                                                                                              msync(
                                                                                                                                                                                  void *
                                                                                                                                                                                      addr,
                                                                                                                                                                                  size_t
                                                                                                                                                                                      len,
                                                                                                                                                                                  int flags); }
a kuku

278	COMPAT_30 MODULAR compat	\
a kuku

279	COMPAT_30 MODULAR compat	\
a kuku

280	COMPAT_30 MODULAR compat	\
a kuku

281	STD 		{ int|sys|14|sigaltstack( \
a kuku

282	STD 		{
                                                                                                                                                                            int |
                                                                                                                                                                                sys |
                                                                                                                                                                                14 |
                                                                                                                                                                                vfork(
                                                                                                                                                                                    void); }
a kuku

283	STD 	RUMP	{ int|sys||__posix_chown(const char *path, uid_t uid, \
a kuku

284	STD 	RUMP	{ int|sys||__posix_fchown(int fd, uid_t uid, \
a kuku

285	STD 	RUMP	{ int|sys||__posix_lchown(const char *path, uid_t uid, \
a kuku

286	STD 	RUMP	{
                                                                                                                                                                                  pid_t | sys ||
                                                                                                                                                                                      getsid(
                                                                                                                                                                                          pid_t
                                                                                                                                                                                              pid); }
a kuku

287	STD 		{
                                                                                                                                                                                  pid_t | sys ||
                                                                                                                                                                                      __clone(
                                                                                                                                                                                          int flags,
                                                                                                                                                                                          void *
                                                                                                                                                                                              stack); }
a kuku

288	STD 	RUMP	{ int|sys||fktrace(int fd, int ops, \
a kuku

289	STD 	RUMP	{ ssize_t|sys||preadv(int fd, \
a kuku

290	STD 	RUMP	{ ssize_t|sys||pwritev(int fd, \
a kuku

291	COMPAT_16 MODULAR compat { int|sys|14|sigaction(int signum, \
a kuku

292	STD 		{
                                                                                                                                                                                          int |
                                                                                                                                                                                              sys |
                                                                                                                                                                                              14 |
                                                                                                                                                                                              sigpending(
                                                                                                                                                                                                  sigset_t *
                                                                                                                                                                                                  set); }
a kuku

293	STD 		{ int|sys|14|sigprocmask(int how, \
a kuku

294	STD 		{
                                                                                                                                                                                            int |
                                                                                                                                                                                                sys |
                                                                                                                                                                                                14 |
                                                                                                                                                                                                sigsuspend(
                                                                                                                                                                                                    const sigset_t
                                                                                                                                                                                                        *set); }
a kuku

295	COMPAT_16 MODULAR compat	\
a kuku

296	STD 	 RUMP	{
                                                                                                                                                                                            int | sys ||
                                                                                                                                                                                                __getcwd(
                                                                                                                                                                                                    char *
                                                                                                                                                                                                        bufp,
                                                                                                                                                                                                    size_t
                                                                                                                                                                                                        length); }
a kuku

297	STD 	 RUMP	{
                                                                                                                                                                                            int | sys ||
                                                                                                                                                                                                fchroot(
                                                                                                                                                                                                    int fd); }
a kuku

298	COMPAT_30 MODULAR compat	\
a kuku

299	COMPAT_30 MODULAR compat	\
a kuku

300	COMPAT_20 MODULAR compat	\
a kuku

301	COMPAT_50 MODULAR sysv_ipc	\
a kuku

302	COMPAT_50 MODULAR sysv_ipc { int|sys|13|msgctl(int msqid, int cmd, \
a kuku

303	COMPAT_50 MODULAR sysv_ipc { int|sys|13|shmctl(int shmid, int cmd, \
a kuku

304	STD 	 RUMP	{
                                                                                                                                                                                                int | sys ||
                                                                                                                                                                                                    lchflags(
                                                                                                                                                                                                        const char
                                                                                                                                                                                                            *path,
                                                                                                                                                                                                        u_long
                                                                                                                                                                                                            flags); }
a kuku

305	NOERR 	RUMP	{
                                                                                                                                                                                                int | sys ||
                                                                                                                                                                                                    issetugid(
                                                                                                                                                                                                        void); }
a kuku

306	STD	RUMP	{ int|sys||utrace(const char *label, void *addr, \
a kuku

307	STD 		{
                                                                                                                                                                                                  int | sys ||
                                                                                                                                                                                                      getcontext(
                                                                                                                                                                                                          struct
                                                                                                                                                                                                          __ucontext *
                                                                                                                                                                                                          ucp); }
a kuku

308	STD 		{
                                                                                                                                                                                                  int | sys ||
                                                                                                                                                                                                      setcontext(
                                                                                                                                                                                                          const struct
                                                                                                                                                                                                          __ucontext
                                                                                                                                                                                                              *ucp); }
a kuku

309	STD 		{ int|sys||_lwp_create(const struct __ucontext *ucp, \
a kuku

310	STD 		{
                                                                                                                                                                                                    int | sys ||
                                                                                                                                                                                                        _lwp_exit(
                                                                                                                                                                                                            void); }
a kuku

311	STD 		{
                                                                                                                                                                                                    lwpid_t |
                                                                                                                                                                                                            sys ||
                                                                                                                                                                                                        _lwp_self(
                                                                                                                                                                                                            void); }
a kuku

312	STD 		{ int|sys||_lwp_wait(lwpid_t wait_for, \
a kuku

313	STD 		{
                                                                                                                                                                                                      int | sys ||
                                                                                                                                                                                                          _lwp_suspend(
                                                                                                                                                                                                              lwpid_t
                                                                                                                                                                                                                  target); }
a kuku

314	STD 		{
                                                                                                                                                                                                      int | sys ||
                                                                                                                                                                                                          _lwp_continue(
                                                                                                                                                                                                              lwpid_t
                                                                                                                                                                                                                  target); }
a kuku

315	STD 		{
                                                                                                                                                                                                      int | sys ||
                                                                                                                                                                                                          _lwp_wakeup(
                                                                                                                                                                                                              lwpid_t
                                                                                                                                                                                                                  target); }
a kuku

316	STD 		{
                                                                                                                                                                                                      void * |
                                                                                                                                                                                                              sys ||
                                                                                                                                                                                                          _lwp_getprivate(
                                                                                                                                                                                                              void); }
a kuku

317	STD 		{
                                                                                                                                                                                                      void | sys ||
                                                                                                                                                                                                          _lwp_setprivate(
                                                                                                                                                                                                              void *
                                                                                                                                                                                                                  ptr); }
a kuku

318	STD 		{
                                                                                                                                                                                                      int | sys ||
                                                                                                                                                                                                          _lwp_kill(
                                                                                                                                                                                                              lwpid_t
                                                                                                                                                                                                                  target,
                                                                                                                                                                                                              int signo); }
a kuku

319	STD 		{
                                                                                                                                                                                                      int | sys ||
                                                                                                                                                                                                          _lwp_detach(
                                                                                                                                                                                                              lwpid_t
                                                                                                                                                                                                                  target); }
a kuku

320	COMPAT_50 MODULAR compat	\
a kuku

321	STD 		{
                                                                                                                                                                                                      int | sys ||
                                                                                                                                                                                                          _lwp_unpark(
                                                                                                                                                                                                              lwpid_t
                                                                                                                                                                                                                  target,
                                                                                                                                                                                                              const void
                                                                                                                                                                                                                  *hint); }
a kuku

322	STD 		{ ssize_t|sys||_lwp_unpark_all(const lwpid_t *targets, \
a kuku

323	STD 		{ int|sys||_lwp_setname(lwpid_t target, \
a kuku

324	STD 		{ int|sys||_lwp_getname(lwpid_t target, \
a kuku

325	STD 		{ int|sys||_lwp_ctl(int features, \
a kuku

326	UNIMPL
a kuku

327	UNIMPL
a kuku

328	UNIMPL
a kuku

329	UNIMPL
a kuku

330	COMPAT_60 	{ int|sys||sa_register(void *newv, void **oldv, \
a kuku

331	COMPAT_60 	{
                                                                                                                                                                                                                int | sys ||
                                                                                                                                                                                                                    sa_stacks(
                                                                                                                                                                                                                        int num,
                                                                                                                                                                                                                        stack_t
                                                                                                                                                                                                                            *stacks); }
a kuku

332	COMPAT_60 	{
                                                                                                                                                                                                                int | sys ||
                                                                                                                                                                                                                    sa_enable(
                                                                                                                                                                                                                        void); }
a kuku

333	COMPAT_60 	{
                                                                                                                                                                                                                int | sys ||
                                                                                                                                                                                                                    sa_setconcurrency(
                                                                                                                                                                                                                        int concurrency); }
a kuku

334	COMPAT_60 	{
                                                                                                                                                                                                                int | sys ||
                                                                                                                                                                                                                    sa_yield(
                                                                                                                                                                                                                        void); }
a kuku

335	COMPAT_60 	{
                                                                                                                                                                                                                int | sys ||
                                                                                                                                                                                                                    sa_preempt(
                                                                                                                                                                                                                        int sa_id); }
a kuku

336	OBSOL 		sys_sa_unblockyield
a kuku

337	UNIMPL
a kuku

338	UNIMPL
a kuku

339	UNIMPL
a kuku

340	STD 		{ int|sys||__sigaction_sigtramp(int signum, \
a kuku

341	STD		{
                                                                                                                                                                                                                  int | sys ||
                                                                                                                                                                                                                      pmc_get_info(
                                                                                                                                                                                                                          int ctr,
                                                                                                                                                                                                                          int op,
                                                                                                                                                                                                                          void *
                                                                                                                                                                                                                              args); }
a kuku

342	STD		{
                                                                                                                                                                                                                  int | sys ||
                                                                                                                                                                                                                      pmc_control(
                                                                                                                                                                                                                          int ctr,
                                                                                                                                                                                                                          int op,
                                                                                                                                                                                                                          void *
                                                                                                                                                                                                                              args); }
a kuku

343	STD 		{
                                                                                                                                                                                                                  int | sys ||
                                                                                                                                                                                                                      rasctl(
                                                                                                                                                                                                                          void *
                                                                                                                                                                                                                              addr,
                                                                                                                                                                                                                          size_t
                                                                                                                                                                                                                              len,
                                                                                                                                                                                                                          int op); }
a kuku

344	STD	RUMP	{
                                                                                                                                                                                                                  int | sys ||
                                                                                                                                                                                                                      kqueue(
                                                                                                                                                                                                                          void); }
a kuku

345	COMPAT_50 MODULAR compat RUMP { int|sys||kevent(int fd, \
a kuku

346	STD 		{ int|sys||_sched_setparam(pid_t pid, lwpid_t lid, \
a kuku

347	STD 		{ int|sys||_sched_getparam(pid_t pid, lwpid_t lid, \
a kuku

348	STD 		{ int|sys||_sched_setaffinity(pid_t pid, lwpid_t lid, \
a kuku

349	STD 		{ int|sys||_sched_getaffinity(pid_t pid, lwpid_t lid, \
a kuku

350	STD 		{
                                                                                                                                                                                                                            int | sys ||
                                                                                                                                                                                                                                sched_yield(
                                                                                                                                                                                                                                    void); }
a kuku

351	STD		{
                                                                                                                                                                                                                            int | sys ||
                                                                                                                                                                                                                                _sched_protect(
                                                                                                                                                                                                                                    int priority); }	
a kuku

352	UNIMPL
a kuku

353	UNIMPL
a kuku

354	STD	RUMP	{ int|sys||fsync_range(int fd, int flags, off_t start, \
a kuku

355	STD 		{
                                                                                                                                                                                                                              int | sys ||
                                                                                                                                                                                                                                  uuidgen(
                                                                                                                                                                                                                                      struct
                                                                                                                                                                                                                                          uuid *
                                                                                                                                                                                                                                          store,
                                                                                                                                                                                                                                      int count); }
a kuku

356	STD 	RUMP	{ int|sys||getvfsstat(struct statvfs *buf, \
a kuku

357	STD 	RUMP	{ int|sys||statvfs1(const char *path, \
a kuku

358	STD 	RUMP	{ int|sys||fstatvfs1(int fd, struct statvfs *buf, \
a kuku

359	COMPAT_30 MODULAR compat	\
a kuku

360	STD 	RUMP	{ int|sys||extattrctl(const char *path, int cmd, \
a kuku

361	STD 	RUMP	{ int|sys||extattr_set_file(const char *path, \
a kuku

362	STD 	RUMP	{ ssize_t|sys||extattr_get_file(const char *path, \
a kuku

363	STD 	RUMP	{ int|sys||extattr_delete_file(const char *path, \
a kuku

364	STD 	RUMP	{ int|sys||extattr_set_fd(int fd, \
a kuku

365	STD 	RUMP	{ ssize_t|sys||extattr_get_fd(int fd, \
a kuku

366	STD 	RUMP	{ int|sys||extattr_delete_fd(int fd, \
a kuku

367	STD 	RUMP	{ int|sys||extattr_set_link(const char *path, \
a kuku

368	STD 	RUMP	{ ssize_t|sys||extattr_get_link(const char *path, \
a kuku

369	STD 	RUMP	{ int|sys||extattr_delete_link(const char *path, \
a kuku

370	STD 	RUMP	{ ssize_t|sys||extattr_list_fd(int fd, \
a kuku

371	STD 	RUMP	{ ssize_t|sys||extattr_list_file(const char *path, \
a kuku

372	STD 	RUMP	{ ssize_t|sys||extattr_list_link(const char *path, \
a kuku

373	COMPAT_50 MODULAR compat RUMP	\
a kuku

374	COMPAT_50 MODULAR compat RUMP	\
a kuku

375	STD 	RUMP	{ int|sys||setxattr(const char *path, \
a kuku

376	STD 	RUMP	{ int|sys||lsetxattr(const char *path, \
a kuku

377	STD 	RUMP	{ int|sys||fsetxattr(int fd, \
a kuku

378	STD 	RUMP	{ int|sys||getxattr(const char *path, \
a kuku

379	STD 	RUMP	{ int|sys||lgetxattr(const char *path, \
a kuku

380	STD 	RUMP	{ int|sys||fgetxattr(int fd, \
a kuku

381	STD 	RUMP	{ int|sys||listxattr(const char *path, \
a kuku

382	STD 	RUMP	{ int|sys||llistxattr(const char *path, \
a kuku

383	STD 	RUMP	{ int|sys||flistxattr(int fd, \
a kuku

384	STD 	RUMP	{ int|sys||removexattr(const char *path, \
a kuku

385	STD 	RUMP	{ int|sys||lremovexattr(const char *path, \
a kuku

386	STD 	RUMP	{ int|sys||fremovexattr(int fd, \
a kuku

387	COMPAT_50 MODULAR compat RUMP	\
a kuku

388	COMPAT_50 MODULAR compat RUMP	\
a kuku

389	COMPAT_50 MODULAR compat RUMP	\
a kuku

390	STD 	RUMP	{
                                                                                                                                                                                                                                                                                      int |
                                                                                                                                                                                                                                                                                          sys |
                                                                                                                                                                                                                                                                                          30 |
                                                                                                                                                                                                                                                                                          getdents(
                                                                                                                                                                                                                                                                                              int fd,
                                                                                                                                                                                                                                                                                              char *
                                                                                                                                                                                                                                                                                                  buf,
                                                                                                                                                                                                                                                                                              size_t
                                                                                                                                                                                                                                                                                                  count); }
a kuku

391	IGNORED		old posix_fadvise
a kuku

392	COMPAT_30 MODULAR compat { int|sys|30|fhstat(const struct compat_30_fhandle \
a kuku

393	COMPAT_50 MODULAR compat	\
a kuku

394	STD	 RUMP	{
                                                                                                                                                                                                                                                                                        int |
                                                                                                                                                                                                                                                                                            sys |
                                                                                                                                                                                                                                                                                            30 |
                                                                                                                                                                                                                                                                                            socket(
                                                                                                                                                                                                                                                                                                int domain,
                                                                                                                                                                                                                                                                                                int type,
                                                                                                                                                                                                                                                                                                int protocol); }
a kuku

395	STD 	 RUMP	{ int|sys|30|getfh(const char *fname, void *fhp, \
a kuku

396	STD 	 RUMP	{ int|sys|40|fhopen(const void *fhp, size_t fh_size,\
a kuku

397	STD 	 RUMP	{ int|sys|40|fhstatvfs1(const void *fhp, \
a kuku

398	COMPAT_50 MODULAR compat RUMP { int|sys|40|fhstat(const void *fhp, \
a kuku

399	STD MODULAR aio RUMP	\
a kuku

400	STD MODULAR aio RUMP	\
a kuku

401	STD MODULAR aio RUMP	\
a kuku

402	STD MODULAR aio RUMP	\
a kuku

403	STD MODULAR aio RUMP	\
a kuku

404	COMPAT_50 MODULAR compat	\
a kuku

405	STD MODULAR aio RUMP	\
a kuku

406	STD MODULAR aio RUMP	\
a kuku

407	UNIMPL
a kuku

408	UNIMPL
a kuku

409	UNIMPL
a kuku

410	STD  RUMP	{ int|sys|50|mount(const char *type, \
a kuku

411	STD 		{ void *|sys||mremap(void *old_address, size_t old_size, \
a kuku

412	STD 		{
                                                                                                                                                                                                                                                                                                    int | sys ||
                                                                                                                                                                                                                                                                                                        pset_create(
                                                                                                                                                                                                                                                                                                            psetid_t *
                                                                                                                                                                                                                                                                                                            psid); }
a kuku

413	STD 		{
                                                                                                                                                                                                                                                                                                    int | sys ||
                                                                                                                                                                                                                                                                                                        pset_destroy(
                                                                                                                                                                                                                                                                                                            psetid_t
                                                                                                                                                                                                                                                                                                                psid); }
a kuku

414	STD 		{ int|sys||pset_assign(psetid_t psid, cpuid_t cpuid, \
a kuku

415	STD 		{ int|sys||_pset_bind(idtype_t idtype, id_t first_id, \
a kuku

416	NOERR RUMP	{ int|sys|50|posix_fadvise(int fd, int PAD, \
a kuku

417	STD  RUMP	{ int|sys|50|select(int nd, fd_set *in, fd_set *ou, \
a kuku

418	STD  RUMP	{ int|sys|50|gettimeofday(struct timeval *tp, \
a kuku

419	STD  RUMP	{ int|sys|50|settimeofday(const struct timeval *tv, \
a kuku

420	STD  RUMP	{ int|sys|50|utimes(const char *path, \
a kuku

421	STD  RUMP	{ int|sys|50|adjtime(const struct timeval *delta, \
a kuku

422	STD  MODULAR lfs { int|sys|50|lfs_segwait(fsid_t *fsidp, \
a kuku

423	STD  RUMP	{ int|sys|50|futimes(int fd, \
a kuku

424	STD  RUMP 	{ int|sys|50|lutimes(const char *path, \
a kuku

425	STD  RUMP	{ int|sys|50|setitimer(int which, \
a kuku

426	STD  RUMP	{ int|sys|50|getitimer(int which, \
a kuku

427	STD  RUMP	{ int|sys|50|clock_gettime(clockid_t clock_id, \
a kuku

428	STD  RUMP	{ int|sys|50|clock_settime(clockid_t clock_id, \
a kuku

429	STD  RUMP	{ int|sys|50|clock_getres(clockid_t clock_id, \
a kuku

430	STD  RUMP	{ int|sys|50|nanosleep(const struct timespec *rqtp, \
a kuku

431	STD 		{ int|sys|50|__sigtimedwait(const sigset_t *set, \
a kuku

432	STD MODULAR mqueue	\
a kuku

433	STD MODULAR mqueue	\
a kuku

434	COMPAT_60 MODULAR compat \
a kuku

435	STD	RUMP	{ int|sys|50|kevent(int fd, \
a kuku

436	STD 	RUMP	{ int|sys|50|pselect(int nd, fd_set *in, fd_set *ou, \
a kuku

437	STD 	RUMP	{ int|sys|50|pollts(struct pollfd *fds, u_int nfds, \
a kuku

438	STD MODULAR aio RUMP { int|sys|50|aio_suspend( \
a kuku

439	STD  RUMP	{
                                                                                                                                                                                                                                                                                                                                                int |
                                                                                                                                                                                                                                                                                                                                                    sys |
                                                                                                                                                                                                                                                                                                                                                    50 |
                                                                                                                                                                                                                                                                                                                                                    stat(
                                                                                                                                                                                                                                                                                                                                                        const char
                                                                                                                                                                                                                                                                                                                                                            *path,
                                                                                                                                                                                                                                                                                                                                                        struct stat *
                                                                                                                                                                                                                                                                                                                                                            ub); }
a kuku

440	STD  RUMP	{
                                                                                                                                                                                                                                                                                                                                                int |
                                                                                                                                                                                                                                                                                                                                                    sys |
                                                                                                                                                                                                                                                                                                                                                    50 |
                                                                                                                                                                                                                                                                                                                                                    fstat(int fd,
                                                                                                                                                                                                                                                                                                                                                          struct
                                                                                                                                                                                                                                                                                                                                                          stat
                                                                                                                                                                                                                                                                                                                                                              *sb); }
a kuku

441	STD  RUMP	{
                                                                                                                                                                                                                                                                                                                                                int |
                                                                                                                                                                                                                                                                                                                                                    sys |
                                                                                                                                                                                                                                                                                                                                                    50 |
                                                                                                                                                                                                                                                                                                                                                    lstat(
                                                                                                                                                                                                                                                                                                                                                        const char
                                                                                                                                                                                                                                                                                                                                                            *path,
                                                                                                                                                                                                                                                                                                                                                        struct stat *
                                                                                                                                                                                                                                                                                                                                                            ub); }
a kuku

442	STD MODULAR sysv_ipc { int|sys|50|__semctl(int semid, int semnum, \
a kuku

443	STD MODULAR sysv_ipc { int|sys|50|shmctl(int shmid, int cmd, \
a kuku

444	STD MODULAR sysv_ipc { int|sys|50|msgctl(int msqid, int cmd, \
a kuku

445	STD 		{
                                                                                                                                                                                                                                                                                                                                                      int |
                                                                                                                                                                                                                                                                                                                                                          sys | 50 | getrusage(int who, struct rusage *rusage); }
a kuku

446	STD  RUMP	{ int|sys|50|timer_settime(timer_t timerid, \
a kuku

447	STD  RUMP	{ int|sys|50|timer_gettime(timer_t timerid, struct \
#if defined(NTP) || !defined(_KERNEL_OPT)
a kuku

448	STD		{
                                                                                                                                                                                                                                                                                                                                                          int |
                                                                                                                                                                                                                                                                                                                                                              sys |
                                                                                                                                                                                                                                                                                                                                                              50 |
                                                                                                                                                                                                                                                                                                                                                              ntp_gettime(
                                                                                                                                                                                                                                                                                                                                                                  struct
                                                                                                                                                                                                                                                                                                                                                                  ntptimeval *
                                                                                                                                                                                                                                                                                                                                                                  ntvp); }
#else
a kuku

    448 EXCL ___ntp_gettime50
#endif
a kuku

449	STD 		{ int|sys|50|wait4(pid_t pid, int *status, \
a kuku

450	STD  RUMP	{ int|sys|50|mknod(const char *path, mode_t mode, \
a kuku

451	STD  RUMP 	{ int|sys|50|fhstat(const void *fhp, \
a kuku

452	OBSOL		5.99 quotactl
a kuku

453	STD  RUMP	{
                                                                                                                                                                                                                                                                                                                                                                int | sys ||
                                                                                                                                                                                                                                                                                                                                                                    pipe2(
                                                                                                                                                                                                                                                                                                                                                                        int *
                                                                                                                                                                                                                                                                                                                                                                            fildes,
                                                                                                                                                                                                                                                                                                                                                                        int flags); }
a kuku

454	STD  RUMP	{
                                                                                                                                                                                                                                                                                                                                                                int | sys ||
                                                                                                                                                                                                                                                                                                                                                                    dup3(
                                                                                                                                                                                                                                                                                                                                                                        int from,
                                                                                                                                                                                                                                                                                                                                                                        int to, int flags); }
a kuku

455	STD  RUMP	{
                                                                                                                                                                                                                                                                                                                                                                int | sys ||
                                                                                                                                                                                                                                                                                                                                                                    kqueue1(
                                                                                                                                                                                                                                                                                                                                                                        int flags); }
a kuku

456	STD  RUMP	{ int|sys||paccept(int s, struct sockaddr *name, \
a kuku

457	STD  RUMP	{ int|sys||linkat(int fd1, const char *name1, \
a kuku

458	STD  RUMP	{ int|sys||renameat(int fromfd, const char *from, \
a kuku

459	STD  RUMP	{ int|sys||mkfifoat(int fd, const char *path, \
a kuku

460	STD  RUMP	{ int|sys||mknodat(int fd, const char *path, \
a kuku

461	STD  RUMP	{ int|sys||mkdirat(int fd, const char *path, \
a kuku

462	STD  RUMP	{ int|sys||faccessat(int fd, const char *path, \
a kuku

463	STD  RUMP	{ int|sys||fchmodat(int fd, const char *path, \
a kuku

464	STD  RUMP	{ int|sys||fchownat(int fd, const char *path, \
a kuku

465	STD  		{ int|sys||fexecve(int fd, \
a kuku

466	STD  RUMP	{ int|sys||fstatat(int fd, const char *path, \
a kuku

467	STD  RUMP	{ int|sys||utimensat(int fd, const char *path, \
a kuku

468	STD  RUMP	{ int|sys||openat(int fd, const char *path, \
a kuku

469	STD  RUMP	{ ssize_t|sys||readlinkat(int fd, const char *path, \
a kuku

470	STD  RUMP	{ int|sys||symlinkat(const char *path1, int fd, \
a kuku

471	STD  RUMP	{ int|sys||unlinkat(int fd, const char *path, \
a kuku

472	STD  RUMP	{ int|sys||futimens(int fd, \
a kuku

473	STD  RUMP	{ int|sys||__quotactl(const char *path, \
a kuku

474	NOERR		{ int|sys||posix_spawn(pid_t *pid, const char *path, \
a kuku

475	STD  RUMP	{ int|sys||recvmmsg(int s, struct mmsghdr *mmsg, \
a kuku

476	STD  RUMP	{ int|sys||sendmmsg(int s, struct mmsghdr *mmsg, \
a kuku

477	NOERR	RUMP	{ int|sys||clock_nanosleep(clockid_t clock_id, \
a kuku

478	STD 		{ int|sys|60|_lwp_park(clockid_t clock_id, int flags, \
a kuku

479	NOERR	RUMP	{ int|sys||posix_fallocate(int fd, int PAD, off_t pos, \
a kuku

480	STD  RUMP	{ int|sys||fdiscard(int fd, int PAD, off_t pos, \
a kuku

481	STD 		{ int|sys||wait6(idtype_t idtype, id_t id, \
a kuku

482	STD		{ int|sys||clock_getcpuclockid2(idtype_t idtype,

#endif // SANITIZER_NETBSD_SYSCALL_HOOKS_H
