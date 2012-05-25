/*
 * wsclean

  Copyright (C) 2012 Ger Hobbelt, www.hebbut.net

  This software is provided 'as-is', without any express or implied
  warranty.  In no event will the authors be held liable for any damages
  arising from the use of this software.

  Permission is granted to anyone to use this software for any purpose,
  including commercial applications, and to alter it and redistribute it
  freely, subject to the following restrictions:

  1. The origin of this software must not be misrepresented; you must not
     claim that you wrote the original software. If you use this software
     in a product, an acknowledgment in the product documentation would be
     appreciated but is not required.
  2. Altered source versions must be plainly marked as such, and must not be
     misrepresented as being the original software.
  3. This notice may not be removed or altered from any source distribution.

*/

/*
This little tool is a quick way to remove empty directories and empty directory trees.

Features:

- recursively removes empty directories
- fast
*/

#include "mongoose_sys_porting.h"  // ripped from my mongoose clone
#include "getopts.h"


#define  ABSPATH_MAX   (PATH_MAX > 1024 ? PATH_MAX * 2 : 2048)


typedef enum command
{
    ARG_HELP = 1,
    ARG_VERBOSE,
} command_t;

static const option_t opts[] =
{
    {
        ARG_HELP,
            "h",
            "help",
            "this help screen",
            0
    },
    {
        ARG_VERBOSE,
            "v",
            "verbose",
            "print process progress to stderr",
            0
    },
    { 0, 0, 0, 0, 0 }               // sentinel
};

const char *filename(const char *path)
{
    const char *delims = "/\\:";

    for ( ; *delims; delims++)
    {
        const char *p = strrchr(path, *delims);
        if (p) path = p + 1;
    }
    return path;
}

static const char **infiles = NULL;

void add_infile(const char *path)
{
    int idx = 0;

    if (!infiles)
    {
        infiles = (const char **)malloc(2 * sizeof(*infiles));
    }
    else
    {
        for (idx = 0; infiles[idx]; idx++)
            ;
        infiles = (const char **)realloc((void *)infiles, (idx + 2) * sizeof(*infiles));
    }
    infiles[idx] = path;
    infiles[++idx] = NULL;
}

typedef struct
{
    unsigned verbose: 2;
} cmd_t;

char *strtolower(char *s)
{
    while (*s)
    {
        if (*s < 127)
        {
            *s = (char)tolower(*s);
        }
        s++;
    }
    return s;
}


int pop_filedef(const char **filepath)
{
    static int idx = 0;

    *filepath = NULL;

    if (idx == 0 && !infiles)
    {
        return 0;
    }
    else if (infiles && infiles[idx])
    {
        *filepath = infiles[idx];
        idx++;
        return 1;
    }
    return 0;
}




// code ripped from mongoose and tweaked:






#if defined(_WIN32) && !defined(__SYMBIAN32__)

// For Windows, change all slashes to backslashes in path names.
static void change_slashes_to_backslashes(char *path) {
  int i;

  for (i = 0; path[i] != '\0'; i++) {
    if (path[i] == '/')
      path[i] = '\\';
    // i > 0 check is to preserve UNC paths, like \\server\file.txt
    if (path[i] == '\\' && i > 0)
      while (path[i + 1] == '\\' || path[i + 1] == '/')
        (void) memmove(path + i + 1,
            path + i + 2, strlen(path + i + 1));
  }
}

// Encode 'path' which is assumed UTF-8 string, into UNICODE string.
// wbuf and wbuf_len is a target buffer and its length.
static void to_unicode(const char *path, wchar_t *wbuf, size_t wbuf_len) {
  char buf[ABSPATH_MAX], buf2[ABSPATH_MAX], *p;

  strncpy(buf, path, sizeof(buf));
  buf[sizeof(buf) - 1] = 0;
  change_slashes_to_backslashes(buf);

  // Point p to the end of the file name
  p = buf + strlen(buf) - 1;

  // Trim trailing backslash character
  while (p > buf && *p == '\\' && p[-1] != ':') {
    *p-- = '\0';
  }

   // Protect from CGI code disclosure.
   // This is very nasty hole. Windows happily opens files with
   // some garbage in the end of file name. So fopen("a.cgi    ", "r")
   // actually opens "a.cgi", and does not return an error!
  if (*p == 0x20 ||               // No space at the end
      (*p == 0x2e && p > buf) ||  // No '.' but allow '.' as full path
      *p == 0x2b ||               // No '+'
      (*p & ~0x7f)) {             // And generally no non-ASCII chars
    fprintf(stderr, "Rejecting suspicious path: [%s]", buf);
    wbuf[0] = L'\0';
  } else {
    // Convert to Unicode and back. If doubly-converted string does not
    // match the original, something is fishy, reject.
    memset(wbuf, 0, wbuf_len*sizeof(wchar_t)); // <bel>: fix otherwise an "uninitialized memory read in WideCharToMultiByte" occurs
    MultiByteToWideChar(CP_UTF8, 0, buf, -1, wbuf, (int) wbuf_len);
    WideCharToMultiByte(CP_UTF8, 0, wbuf, (int) wbuf_len, buf2, sizeof(buf2),
                        NULL, NULL);
    if (strcmp(buf, buf2) != 0) {
	  fprintf(stderr, "Rejecting malicious path: [%s]", buf);
      wbuf[0] = L'\0';
    }
  }
}




static int clean_dirtree_w(const wchar_t *dir, const wchar_t *dir4err, const cmd_t *cmd) 
{
  wchar_t path[ABSPATH_MAX];
  wchar_t *p;
  HANDLE handle;
  WIN32_FIND_DATAW info;

	wcscpy(path, dir);
    (void) wcscat(path, L"\\");
	p = path + wcslen(path);
    (void) wcscat(p, L"*");

      handle = FindFirstFileW(path, &info);
	  if (handle == INVALID_HANDLE_VALUE)
	  {
		  return 0;
	}
  else 
  {
	  int counter = 0;
	  int failure_heuristic = 5;

        if (cmd->verbose > 1) fprintf(stderr, "Processing: %S\n", (cmd->verbose > 2 ? dir : dir4err));
        else if (cmd->verbose == 1) fputc('.', stderr);

	  while (failure_heuristic)
	  {
		  // Do not show current dir
		  if (wcscmp(info.cFileName, L".") &&
			  wcscmp(info.cFileName, L".."))
		  {
			  if (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) 
			  {
				  int rv;

				  wcscpy(p, info.cFileName);
				rv = clean_dirtree_w(path, info.cFileName, cmd);
				if (0 == rv)
				{
					if (RemoveDirectoryW(path))
					{
				        if (cmd->verbose > 1) fprintf(stderr, "Removed: %S\n", (cmd->verbose > 2 ? path : info.cFileName));
				        else if (cmd->verbose == 1) fputc('+', stderr);
					}
				}
				else if (rv > 0)
					counter += rv;
			  }
			  else
			  {
				  counter++;
			  }
		  }

		  while (!FindNextFileW(handle, &info) && failure_heuristic)
			{
				if (GetLastError() == ERROR_NO_MORE_FILES)
				{
					failure_heuristic = 0;
					break;
				}
				failure_heuristic--;
			  counter++;
		  }
	  }
      FindClose(handle);

	// return file counter: when > 0, don't even try to remove the parent dir - optimization
	return counter;
  }
}


static int clean_dirtree(const char *dir, const cmd_t *cmd) 
{
  wchar_t wbuf[ABSPATH_MAX];

  if (!dir)
	  return -1;

  to_unicode(dir, wbuf, ARRAY_SIZE(wbuf));

  if (wbuf[0])
  {
	  int rv;
	  
	  rv = clean_dirtree_w(wbuf, wbuf, cmd);
       if (cmd->verbose == 1) fputc('\n', stderr);
	   return rv;
  }
  return -1;
}



#else

static int clean_dirtree(const char *dir, const cmd_t *cmd) 
{
  char path[ABSPATH_MAX];
  struct dirent *dp;
  struct stat st;
  DIR *dirp;

  if ((dirp = opendir(dir)) == NULL) {
    return 0;
  } 
  else 
  {
	  int counter = 0;

    while ((dp = readdir(dirp)) != NULL) 
	{
		struct mgstat st;

      // Do not show current dir
      if (!strcmp(dp->d_name, ".") ||
          !strcmp(dp->d_name, ".."))
        continue;

      snprintf(path, sizeof(path), "%s%c%s", dir, '/', dp->d_name);

      if (stat(path, &st) != 0) 
	  {
        memset(&st, 0, sizeof(st));
      }

	  if (S_ISDIR(st.st_mode))
	  {
		int rv = clean_dirtree(path);

		if (0 == rv)
		{
			rmdir(path);
		}
		else if (rv > 0)
		{
			counter += rv;
		}
	  }
	  else
		  counter++;
    }
    (void) closedir(dirp);

	// return file counter: when > 0, don't even try to remove the parent dir - optimization
	return counter;
  }
}

#endif // _WIN32




int main(int argc, const char **argv)
{
    unsigned int opt;
    const char *param;
    const char *appname = filename(argv[0]);
    cmd_t cmd = {0};
    const char *fpath;
    const char *fname;
    const char *fname4err;

    getopts_init(argc, argv, appname);

    for (;;)
    {
        char *p;
        unsigned long l;

        opt = getopts(opts, &param);
        switch (opt)
        {
        case 0:
            break;

        case ARG_HELP:
            getopts_usage(opts);
            exit(EXIT_FAILURE);

        case ARG_VERBOSE:
            cmd.verbose++;
            if (cmd.verbose == 0) cmd.verbose = ~0u;
            continue;

		case GETOPTS_PARAMETER:
			add_infile(param);
			continue;

        case GETOPTS_UNKNOWN:
            printf("%s: unknown parameter %s\n", appname, param);
            exit(EXIT_FAILURE);

        case GETOPTS_MISSING_PARAM:
            printf("%s: option %s is missing a mandatory parameter\n", appname, param);
            exit(EXIT_FAILURE);
        }
        break;
    }

    fflush(stdout);

    while (pop_filedef(&fpath))
    {
        fname = filename(fpath);

        fname4err = fname;
        if (!*fname4err)
            fname4err = fpath;

        if (cmd.verbose) fprintf(stderr, "Processing: %s\n", (cmd.verbose != 2 ? fpath : fname4err));

		clean_dirtree(fpath, &cmd);
	}
	
    if (fpath != NULL)
    {
        fname = filename(fpath);

		fname4err = fname;
		if (!*fname4err)
			fname4err = fpath;

		fprintf(stderr, "*** ERROR: cannot open file '%s' for reading...\n", (cmd.verbose ? fpath : fname4err));
		exit(EXIT_FAILURE);
	}

	if (cmd.verbose) fprintf(stderr, "Processing: ---done---\n");
	exit(EXIT_SUCCESS);
}

