bdrewery:
 - Refactor and simplify original commit.
 - Stop setting TERM=su without a term.

------------------------------------------------------------------------
r99055 | des | 2002-06-29 04:21:58 -0700 (Sat, 29 Jun 2002) | 6 lines
Changed paths:
   M /head/crypto/openssh/session.c

Make sure the environment variables set by setusercontext() are passed on
to the child process.

Reviewed by:    ache
Sponsored by:   DARPA, NAI Labs

--- session.c.orig	2021-04-15 20:55:25.000000000 -0700
+++ session.c	2021-04-27 13:11:13.515917000 -0700
@@ -939,6 +939,9 @@ do_setup_env(struct ssh *ssh, Session *s, const char *
 	struct passwd *pw = s->pw;
 #if !defined (HAVE_LOGIN_CAP) && !defined (HAVE_CYGWIN)
 	char *path = NULL;
+#else
+	extern char **environ;
+	char **senv, **var, *val;
 #endif
 
 	/* Initialize the environment. */
@@ -960,6 +963,9 @@ do_setup_env(struct ssh *ssh, Session *s, const char *
 	}
 #endif
 
+	if (getenv("TZ"))
+		child_set_env(&env, &envsize, "TZ", getenv("TZ"));
+
 #ifdef GSSAPI
 	/* Allow any GSSAPI methods that we've used to alter
 	 * the child's environment as they see fit
@@ -977,11 +983,30 @@ do_setup_env(struct ssh *ssh, Session *s, const char *
 	child_set_env(&env, &envsize, "LOGIN", pw->pw_name);
 #endif
 	child_set_env(&env, &envsize, "HOME", pw->pw_dir);
+	snprintf(buf, sizeof buf, "%.200s/%.50s", _PATH_MAILDIR, pw->pw_name);
+	child_set_env(&env, &envsize, "MAIL", buf);
 #ifdef HAVE_LOGIN_CAP
-	if (setusercontext(lc, pw, pw->pw_uid, LOGIN_SETPATH) < 0)
-		child_set_env(&env, &envsize, "PATH", _PATH_STDPATH);
-	else
-		child_set_env(&env, &envsize, "PATH", getenv("PATH"));
+	child_set_env(&env, &envsize, "PATH", _PATH_STDPATH);
+	child_set_env(&env, &envsize, "TERM", "su");
+	/*
+	 * Temporarily swap out our real environment with an empty one,
+	 * let setusercontext() apply any environment variables defined
+	 * for the user's login class, copy those variables to the child,
+	 * free the temporary environment, and restore the original.
+	 */
+	senv = environ;
+	environ = xmalloc(sizeof(*environ));
+	*environ = NULL;
+	(void)setusercontext(lc, pw, pw->pw_uid, LOGIN_SETENV|LOGIN_SETPATH);
+	for (var = environ; *var != NULL; ++var) {
+		if ((val = strchr(*var, '=')) != NULL) {
+			*val++ = '\0';
+			child_set_env(&env, &envsize, *var, val);
+		}
+		free(*var);
+	}
+	free(environ);
+	environ = senv;
 #else /* HAVE_LOGIN_CAP */
 # ifndef HAVE_CYGWIN
 	/*
@@ -1001,17 +1026,9 @@ do_setup_env(struct ssh *ssh, Session *s, const char *
 # endif /* HAVE_CYGWIN */
 #endif /* HAVE_LOGIN_CAP */
 
-	if (!options.use_pam) {
-		snprintf(buf, sizeof buf, "%.200s/%.50s",
-		    _PATH_MAILDIR, pw->pw_name);
-		child_set_env(&env, &envsize, "MAIL", buf);
-	}
-
 	/* Normal systems set SHELL by default. */
 	child_set_env(&env, &envsize, "SHELL", shell);
 
-	if (getenv("TZ"))
-		child_set_env(&env, &envsize, "TZ", getenv("TZ"));
 	if (s->term)
 		child_set_env(&env, &envsize, "TERM", s->term);
 	if (s->display)
@@ -1225,7 +1242,8 @@ do_nologin(struct passwd *pw)
 do_nologin(struct passwd *pw)
 {
 	FILE *f = NULL;
-	char buf[1024], *nl, *def_nl = _PATH_NOLOGIN;
+	const char *nl;
+	char buf[1024], *def_nl = _PATH_NOLOGIN;
 	struct stat sb;
 
 #ifdef HAVE_LOGIN_CAP
@@ -1315,7 +1333,7 @@ do_setusercontext(struct passwd *pw)
 	if (platform_privileged_uidswap()) {
 #ifdef HAVE_LOGIN_CAP
 		if (setusercontext(lc, pw, pw->pw_uid,
-		    (LOGIN_SETALL & ~(LOGIN_SETPATH|LOGIN_SETUSER))) < 0) {
+		    (LOGIN_SETALL & ~(LOGIN_SETENV|LOGIN_SETPATH|LOGIN_SETUSER))) < 0) {
 			perror("unable to set user context");
 			exit(1);
 		}
