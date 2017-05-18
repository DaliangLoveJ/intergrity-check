#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/xattr.h>
#include <linux/capability.h>
#include <regex.h>

#define BASE 10

static char *strtrimr(char *pstr);
static char *strtriml(char *pstr);
static char *strtrim(char *pstr);
int char_to_int(char a);
char int_to_hex(int n);
char *fd_encrypt(char *src);
void usage();
ssize_t read_lmine(int fd, void *vptr, ssize_t maxlen);
int create_hash_info_file(char *filename);
int create_hash_info_ea(char *filename);
int create_file_table(char *mac_dir, char *trustlist);
static ssize_t cread(int fd, char *ptr);

int check_program_trusted(char *filename);
int delete_hashinfo_ea(char *filename);
int delete_hash_info_file(char *filename);
int copyfilecontent(char *srcfile, char *dstfile);
int check_bash();
int check_login();
int update_program_hashinfo(char *filename);
char *fd_calculate(char *filename, char *alg);
void fd_write_conf(char *conf, char *buffer);
char *fd_read_conf(char *conf, int size);
int fd_check_repeat(char *pattern, char *source, regmatch_t pmatch[]);
void fd_write_ldd(char *filename, char *map_filename, char *ldd_filename);
void fd_write_bin_conf(char *filename, char *enc_md5, char *enc_sha256, char *bin_filename);
int check_lib_so(char *binprm);

#define MAC_DIR       "/etc/mac_conf"
#define TRUSTFILE     "/etc/mac_conf/trust_bin_list"
#define TRUSTFILE_D   "/etc/mac_conf/trust_bin_swap"

#define TRUSTFILE_MAP   "/etc/mac_conf/trust_map_list"
#define TRUSTFILE_SO    "/etc/mac_conf/trust_so_list"

#define TOTAL         4096


typedef struct hash_info
{
    char name[256];
    char enc_md5[33];
    char enc_sha256[65];
    struct hash_info *next;
}HashInfo ,*info_hash;


int main(int argc, char **argv)  
{  
    //int ret = create_file_table(MAC_DIR, TRUSTFILE);
    int result;
    opterr = 0;
    
    while((result = getopt(argc, argv, "a:v:d:u:l:t:h")) != -1) 
    {
        switch(result)
	{
            case 'a':
                  create_hash_info_file(optarg);
		  create_hash_info_ea(optarg);
                  break;
            case 'd':
                  delete_hashinfo_ea(optarg);
		  delete_hash_info_file(optarg);
                  printf("Delete file hash info successfully.\n");
	          break;
            case 'v':
                  check_program_trusted(optarg);
                  break;
            case 'u':
                  update_program_hashinfo(optarg);
                  break;
            case 'l':
                  fd_write_ldd(optarg, TRUSTFILE_MAP, TRUSTFILE_SO);
                  break;
            case 't':
                  check_lib_so(optarg);
                  break;
            default:
                  usage();
                  break;
        }
    }
    switch (argc)
    {
        case 1: 
              usage(); 
              break;
    }  
}

int create_hash_info_file(char *filename)
{
        struct stat file_stat;
        int retd;
        retd = stat(filename, &file_stat);
        if(retd < 0)
        {
            if(errno == ENOENT)
            {
                printf("Can not find this bin program: %s\n",filename);
                return EXIT_FAILURE;
            }
        }
        FILE *fp;
	char md5_cmd[80] = {"/usr/bin/md5sum "};
	char sha256_cmd[80] = {"/usr/bin/sha256sum "};
	char md5[33];
	char sha256[65];
	char *new_cmd = strcat(md5_cmd, filename);
	char *enc_md5, *enc_sha256;

	fp = popen(new_cmd, "r");
	fgets(md5, sizeof(md5), fp);
	pclose(fp);

	new_cmd = strcat(sha256_cmd, filename);
	fp = popen(new_cmd, "r");
	fgets(sha256, sizeof(sha256), fp);
	pclose(fp);
	enc_md5 = fd_encrypt(md5);
	enc_sha256 = fd_encrypt(sha256);
    
        char hashinfo[150];
        char compareinfo[150];
        snprintf(hashinfo, sizeof(hashinfo),"%s %s %s\n", filename, enc_md5, enc_sha256);
        int trustfd;

        int existflag = -1;
        int exist[TOTAL];
        int noexist[TOTAL];

        FILE *trustfp;
        char line[1024];
        fp = fopen(TRUSTFILE, "r");
        if(fp == NULL)
                return 1;
        if(!fgets(line, 1023, fp))
        {
             existflag = 0;
        }
        else
        {
            memset(exist, 0, sizeof(exist));
            memset(line, 0, sizeof(line));
            fseek(fp, 0, SEEK_SET);
            while (fgets(line, 1023, fp))
            {   
                //printf("%s\n", line);
                if( strcmp(hashinfo, line) == 0)
                {
                     existflag = 1;                    
                }
           }
        }
        fclose(fp);
        free(enc_md5);
	free(enc_sha256);
        
       
        if(existflag == 1)
        {
            printf("The hash information has been written to the local file before.\n");
        }
        else
        {
            trustfd = open(TRUSTFILE, O_RDWR);
            if(!trustfd)
            {
                printf("Can't open %s: %s\n", TRUSTFILE, strerror (errno));
                return -1;
            }
	    off_t end = lseek(trustfd, 0, SEEK_END);
	    ssize_t flagelse = write(trustfd, hashinfo, strlen(hashinfo));
	    if(flagelse > 0)
	    {
		printf("The hash information was successfully written to the local file.\n");
	    }	
	    close(trustfd); 
        }
  	return 0;  
}

int create_hash_info_ea(char *filename)
{
	struct stat file_stat;
        int retd;
        retd = stat(filename, &file_stat);
        if(retd < 0)
        {
            if(errno == ENOENT)
            {
                printf("Can not find this bin program: %s\n",filename);
                return EXIT_FAILURE;
            }
        }

        FILE *fp;
	char md5_cmd[80] = {"/usr/bin/md5sum "};
	char sha256_cmd[80] = {"/usr/bin/sha256sum "};
	char md5[33];
	char sha256[65];
	char *new_cmd = strcat(md5_cmd, filename);
	char *enc_md5, *enc_sha256;
	int exist = -1;
	
	fp = popen(new_cmd, "r");
	fgets(md5, sizeof(md5), fp);
	pclose(fp);

	new_cmd = strcat(sha256_cmd, filename);
	fp = popen(new_cmd, "r");
	fgets(sha256, sizeof(sha256), fp);
	pclose(fp);
	enc_md5 = fd_encrypt(md5);
	enc_sha256 = fd_encrypt(sha256);
        char hashinfo[100];
        snprintf(hashinfo, sizeof(hashinfo),"%s %s", enc_md5, enc_sha256);      
        int flag = setxattr(filename, "user.security", hashinfo, strlen(hashinfo), 0);
	if (!flag)
	{
		printf("The hash information was successfully written to EA.\n");
	}   
        return 0;
}

int create_file_table(char *mac_dir, char *trustlist)
{
    struct stat file_stat;
    int retd, retf;  
    int listfp;    
    umask(0);    
    retd = stat(mac_dir, &file_stat);
    if(retd < 0)
    {
        if(errno == ENOENT)
        {
            retd = mkdir(mac_dir, S_IRWXU | S_IRWXG | S_IRWXO);
            if(retd < 0)
            {
                return EXIT_FAILURE;  
            }
        }
        else
        {
            return EXIT_FAILURE;  
        }
    }
    memset(&file_stat, 0, sizeof(file_stat));
    retf = stat(trustlist, &file_stat);
    if(retf < 0)
    {
        if(errno == ENOENT)
        {
            listfp = open(trustlist, O_RDWR | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
            if (listfp < 0)
            {
                return EXIT_FAILURE;
            }
            else
            {
                return EXIT_FAILURE;
            }
            close(listfp);
        }
     }
    return 1;
}

#define MAXLINE  256
static ssize_t cread(int fd, char *ptr)
{
    static int read_cnt;
    static char *read_ptr;
    static char read_buf[MAXLINE];
    if (read_cnt <= 0)
    {
    again:
        if ((read_cnt = read(fd, read_buf, sizeof(read_buf))) < 0)
        {
            if (errno == EINTR)
                goto again;
            return(-1);
        } else if (read_cnt == 0)
           return(0);
        read_ptr = read_buf;
    }
    read_cnt--;
    *ptr = *read_ptr++;
    return(1);
}

ssize_t read_line(int fd, void *vptr, ssize_t maxlen)
{
	ssize_t n, rc;
	char c, *ptr;

	ptr = vptr;
	for (n = 1; n < maxlen; n++)
	{
		if ((rc = cread(fd, &c)) == 1)
		{
			*ptr++ = c;
			if (c == '\n')
			break;
		}
		else if (rc == 0)
		{
			*ptr = 0;
			return(n - 1);
		} else
			return(-1);
	}
	*ptr = 0;
	return(n);
}

int check_program_trusted(char *filename)
{
    struct stat file_stat;
    int retd;
    retd = stat(filename, &file_stat);
    if(retd < 0)
    {
        if(errno == ENOENT)
        {
            printf("Can not find this bin program: %s\n",filename);
            return EXIT_FAILURE;
        }
    }
    FILE *fp;
    char md5_cmd[80] = {"/usr/bin/md5sum "};
    char sha256_cmd[80] = {"/usr/bin/sha256sum "};
    char md5[33];
    char sha256[65];
    char *new_cmd = strcat(md5_cmd, filename);
    char *enc_md5, *enc_sha256;

    int eaexist = -1;
    int checkparent = -1; 

    int trustfd;
    fp = popen(new_cmd, "r");
    fgets(md5, sizeof(md5), fp);
    pclose(fp);
    new_cmd = strcat(sha256_cmd, filename);
    fp = popen(new_cmd, "r");
    fgets(sha256, sizeof(sha256), fp);
    pclose(fp);
    enc_md5 = fd_encrypt(md5);
    enc_sha256 = fd_encrypt(sha256);
    char filehashinfo[160];
    char eahashinfo[100];
    snprintf(filehashinfo, sizeof(filehashinfo),"%s %s %s", filename, enc_md5, enc_sha256);    
    snprintf(eahashinfo, sizeof(eahashinfo),"%s %s", enc_md5, enc_sha256);
    
    //get hash info from ea
    ssize_t retea;
    char readea[160];
    char readfile[160];
    memset(readea, 0, sizeof(readea));
    retea = getxattr(filename, "user.security", readea, sizeof(readea));
    if( retea < 0)
    {
        //can not read hash info from ea
        //read from local file then judge
        memset(readfile, 0, sizeof(readfile));
        trustfd  = open(TRUSTFILE, O_RDWR);
        while(read_line(trustfd, readfile, 160) > 0)
        {
            if(strcmp(filehashinfo, readfile) == 0)
            {
                eaexist = 1;  //can find hash info in local file and equal
            } 
            else
            {
                eaexist = 2; // can not find hash info in local file
            }
        } 
        close(trustfd);       
    }
    // read hash info from ea then compare
    if(strlen(readea) > 0)
    {
	if(strcmp(eahashinfo, readea) != 0)
        {
            eaexist = 0;
        }
        else
        { 
            eaexist = 1;
        }
    }
		
    //Total check hash info
    if(eaexist == 1)
    {
        //printf("This program self is trusted.\n");
	int retb = check_bash();
	if(retb == 1)
        {
            int retl = check_login();
            if( retl == 1)
            {
                return 1;    
            }
        }        
    }    
    else if(eaexist == 0)
    {
        printf("The program self hash info is not equal. Prohibit execution.\n");
        return -1;
    }
    else if( eaexist == 2)
    {
        printf("The program self hash info is not exist. You can execute it manually, but please careful.\n");
        return 0;
    }
}


int delete_hashinfo_ea(char *filename)
{
   int retd;
   struct stat file_stat;
   retd = stat(filename, &file_stat);
   if(retd < 0)
   {
       if(errno == ENOENT)
       {
           printf("Can not find this bin program: %s\n",filename);
           return EXIT_FAILURE;
       }
   }
   int reta = removexattr(filename, "user.security");
}

int delete_hash_info_file(char *filename)
{
    //filename check
    if (strcmp(filename, "/usr/bin/login") == 0)
    {
        return ;
    }
    if (strcmp(filename, "/usr/bin/bash") == 0)
    {
        return ;
    }

    //int ret;
    //int dfp;
    //struct stat file_stat;
    //ret = stat(TRUSTFILE_D, &file_stat);
    //if( ret < 0)
    //{
    //    if(errno == ENOENT)
    //    {
    //        dfp = open(TRUSTFILE_D, O_RDWR | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
    //        if( dfp < 0)
    //        {
    //            return EXIT_FAILURE;
    //        }
    //        else
    //        {
    //            return EXIT_FAILURE;
    //        }
    //        close(dfp);
    //    }         
    //}
	
    char line[1024];
    char tmpbuf[1024];
    FILE *fp;
    FILE *tdfp;
    fp = fopen(TRUSTFILE,"r");
    if(fp == NULL)
        return 1;
    tdfp = fopen(TRUSTFILE_D, "w+");
    if(tdfp == NULL)
        return 1;

    while (fgets(line, 1023, fp))
    {
         memset(tmpbuf, 0, sizeof(tmpbuf));
         strcpy(tmpbuf, line);
 	 char *p = strtrim(line);
         int len = strlen(p);
         if(len <= 0)
	 {
             return 1;//空行
         }
         else
	 {
            char *p2 = strchr(p, ' ');
            *p2++ = '\0';
	    if(strcmp(p, filename) == 0)
	    {
	       continue;
	    }
	    else
	    {  
                //printf("%s\n", tmpbuf); 
	        fprintf(tdfp, "%s",tmpbuf);      
	    }
        }
     }
     fclose(fp);
     fclose(tdfp);
     copyfilecontent(TRUSTFILE_D, TRUSTFILE);	
     //remove(TRUSTFILE_D);
}

int copyfilecontent(char *srcfile, char *dstfile)
{
    FILE *srcfp;
    FILE *dstfp;
    char line[1024];
    srcfp = fopen(TRUSTFILE_D, "r");
    if(srcfp == NULL)
        return 1;  
    dstfp = fopen(TRUSTFILE, "w+");
    if(dstfp == NULL)
        return 1;
    
    while(fgets(line, 1023,srcfp))
    {
        fprintf(dstfp, "%s", line);  
    }    
    fclose(srcfp);
    fclose(dstfp);
}

int check_bash()
{
    char *filename = "/usr/bin/bash";
    FILE *fp;
    char md5_cmd[80] = {"/usr/bin/md5sum "};
    char sha256_cmd[80] = {"/usr/bin/sha256sum "};
    char md5[33];
    char sha256[65];
    char *new_cmd = strcat(md5_cmd, filename);
    char *enc_md5, *enc_sha256;
    int eaexist = -1;

    int trustfd;
    fp = popen(new_cmd, "r");
    fgets(md5, sizeof(md5), fp);
    pclose(fp);
    new_cmd = strcat(sha256_cmd, filename);
    fp = popen(new_cmd, "r");
    fgets(sha256, sizeof(sha256), fp);
    pclose(fp);
    enc_md5 = fd_encrypt(md5);
    enc_sha256 = fd_encrypt(sha256);
    char filehashinfo[160];
    char eahashinfo[100];
    snprintf(filehashinfo, sizeof(filehashinfo),"%s %s %s", filename, enc_md5, enc_sha256);    
    snprintf(eahashinfo, sizeof(eahashinfo),"%s %s", enc_md5, enc_sha256);
	
    ssize_t retea;
    char readea[160];
    char readfile[160];
    memset(readea, 0, sizeof(readea));
    retea = getxattr(filename, "user.security", readea, sizeof(readea));
    if( retea < 0)
    {
        memset(readfile, 0, sizeof(readfile));
        trustfd  = open(TRUSTFILE, O_RDWR);
        while(read_line(trustfd, readfile, 160) > 0)
        {
            if(strcmp(filehashinfo, readfile) == 0)
            {
                eaexist = 1;  //can find hash info in local file and equal
            } 
            else
            {
                eaexist = 2; // can not find hash info in local file
            }
        } 
        close(trustfd);       
    }
    // read hash info from ea then compare
    if(strlen(readea) > 0)
    {
	if(strcmp(eahashinfo, readea) != 0)
        {
            //equal string 
            eaexist = 0;
        }
        else
        { 
            eaexist = 1;
        }
    }
    //Total check hash info
    if(eaexist == 1)
    {
        //printf("The  parent process bash is trusted.\n");
        return 1;
    }    
    else if(eaexist == 0)
    {
        printf("The parent process bash hash info is not equal. Prohibit execution.\n");
        return -1;
    }
    else if( eaexist == 2)
    {
        printf("The parent process bash hash info is not exist.\n");
        return 0;
    }
}

int check_login()
{
    char *filename = "/usr/bin/login";
    FILE *fp;
    char md5_cmd[80] = {"/usr/bin/md5sum "};
    char sha256_cmd[80] = {"/usr/bin/sha256sum "};
    char md5[33];
    char sha256[65];
    char *new_cmd = strcat(md5_cmd, filename);
    char *enc_md5, *enc_sha256;
    int eaexist = -1;
    int trustfd;
    fp = popen(new_cmd, "r");
    fgets(md5, sizeof(md5), fp);
    pclose(fp);
    new_cmd = strcat(sha256_cmd, filename);
    fp = popen(new_cmd, "r");
    fgets(sha256, sizeof(sha256), fp);
    pclose(fp);
    enc_md5 = fd_encrypt(md5);
    enc_sha256 = fd_encrypt(sha256);
    char filehashinfo[160];
    char eahashinfo[100];
    snprintf(filehashinfo, sizeof(filehashinfo),"%s %s %s\n", filename, enc_md5, enc_sha256);    
    snprintf(eahashinfo, sizeof(eahashinfo),"%s %s", enc_md5, enc_sha256);
    ssize_t retea;
    char readea[160];
    char readfile[160];
    memset(readea, 0, sizeof(readea));
    retea = getxattr(filename, "user.security", readea, sizeof(readea));
    if( retea < 0)
    {
        memset(readfile, 0, sizeof(readfile));
        trustfd  = open(TRUSTFILE, O_RDWR);
        while(read_line(trustfd, readfile, 160) > 0)
        {
            if(strcmp(filehashinfo, readfile) == 0)
            {
                eaexist = 1;  //can find hash info in local file and equal
            } 
            else
            {
                eaexist = 2; // can not find hash info in local file
            }
        } 
        close(trustfd);       
    }
    if(strlen(readea) > 0)
    {
	if(strcmp(eahashinfo, readea) != 0)
        {
            eaexist = 0;
        }
        else
        { 
            eaexist = 1;
        }
    }

    if(eaexist == 1)
    {
        //printf("The  trusted root login program is trusted. This program is trusted.\n");
        printf("This program is trusted.\n");
        return 1;
    }    
    else if(eaexist == 0)
    {
        printf("The trusted root login program hash info is not equal. Prohibit this program execution.\n");
        return -1;
    }
    else if( eaexist == 2)
    {
        printf("The trusted root login program hash info is not exist. You can execute program manually.\n");
        return 0;
    }
}


int run_program_trusted(char *filename)
{
    struct stat file_stat;
    int retd;
    retd = stat(filename, &file_stat);
    if(retd < 0)
    {
        if(errno == ENOENT)
        {
            printf("Can not find this bin program: %s\n",filename);
            return EXIT_FAILURE;
        }
    }
    FILE *fp;
    char md5_cmd[80] = {"/usr/bin/md5sum "};
    char sha256_cmd[80] = {"/usr/bin/sha256sum "};
    char md5[33];
    char sha256[65];
    char *new_cmd = strcat(md5_cmd, filename);
    char *enc_md5, *enc_sha256;

    int eaexist = -1;
    int checkparent = -1; 

    int trustfd;
    fp = popen(new_cmd, "r");
    fgets(md5, sizeof(md5), fp);
    pclose(fp);
    new_cmd = strcat(sha256_cmd, filename);
    fp = popen(new_cmd, "r");
    fgets(sha256, sizeof(sha256), fp);
    pclose(fp);
    enc_md5 = fd_encrypt(md5);
    enc_sha256 = fd_encrypt(sha256);
    char filehashinfo[160];
    char eahashinfo[100];
    snprintf(filehashinfo, sizeof(filehashinfo),"%s %s %s", filename, enc_md5, enc_sha256);    
    snprintf(eahashinfo, sizeof(eahashinfo),"%s %s", enc_md5, enc_sha256);
    
    //get hash info from ea
    ssize_t retea;
    char readea[160];
    char readfile[160];
    memset(readea, 0, sizeof(readea));
    retea = getxattr(filename, "user.security", readea, sizeof(readea));
    if( retea < 0)
    {
        //can not read hash info from ea
        //read from local file then judge
        memset(readfile, 0, sizeof(readfile));
        trustfd  = open(TRUSTFILE, O_RDWR);
        while(read_line(trustfd, readfile, 160) > 0)
        {
            if(strcmp(filehashinfo, readfile) == 0)
            {
                eaexist = 1;  //can find hash info in local file and equal
            } 
            else
            {
                eaexist = 2; // can not find hash info in local file
            }
        } 
        close(trustfd);       
    }
    if(strlen(readea) > 0)
    {
	if(strcmp(eahashinfo, readea) != 0)
        {
            eaexist = 0;
        }
        else
        { 
            eaexist = 1;
        }
    }
		
    //Total check hash info
    if(eaexist == 1)
    {
        printf("This program self is trusted.\n");
	int retb = check_bash();
	if(retb == 1)
        {
            int retl = check_login();
            if( retl == 1)
            {
	        return 1;
            }
        }        
    }    
    else if(eaexist == 0)
    {
        printf("The program self hash info is not equal. Prohibit execution.\n");
        return -1;
    }
    else if( eaexist == 2)
    {
        printf("The program self hash info is not exist. You can execute it manually.\n");
        return 0;
    }
}


int update_program_hashinfo(char *filename)
{
	struct stat file_stat;
	int retd;
	retd = stat(filename, &file_stat);
	if(retd < 0)
	{
		if(errno == ENOENT)
		{
			printf("Can not find this bin program: %s\n",filename);
			return EXIT_FAILURE;
		}
	}
	delete_hash_info_file(filename);
	create_hash_info_file(filename);
	delete_hashinfo_ea(filename);
	create_hash_info_ea(filename);
}


int char_to_int(char a)
{
	int ret = 0;
	switch (a) {
		case '0':
			ret = 0;
			break;
		case '1':
			ret = 1;
			break;
		case '2':
			ret = 2;
			break;
		case '3':
			ret = 3;
			break;
		case '4':
			ret = 4;
			break;
		case '5':
			ret = 5;
			break;
		case '6':
			ret = 6;
			break;
		case '7':
			ret = 7;
			break;
		case '8':
			ret = 8;
			break;
		case '9':
			ret = 9;
			break;
		case 'a':
			ret = 10;
			break;
		case 'b':
			ret = 11;
			break;
		case 'c':
			ret = 12;
			break;
		case 'd':
			ret = 13;
			break;
		case 'e':
			ret = 14;
			break;
		case 'f':
			ret = 15;
			break;
	}

	return ret;

}

char int_to_hex(int n)
{
	if(n >= 10 && n <= 15)
	{
		return 'a' + n - 10;
	}
	return '0' + n;
}

char *fd_encrypt(char *src)
{
	char *target;
	int i, tmp, result;

	target = malloc(strlen(src));
	for(i = 0; i < strlen(src); i++) {
		tmp = char_to_int(src[i]);
		result = tmp ^ BASE;
		target[i] = int_to_hex(result);
	}
	target[i] = '\0';
	return target;
        free(target);
}

void usage()
{
    printf("Usage:    intergrity-check [options] filename( absolute path ) \n");
    printf("Function:  credible verification of executable programs \n");
    printf("           -a  Add bin program hash info to local file and EA \n");
    printf("           -d  Delete hash info stored in local file and EA\n");
    printf("           -u  Update the hash info\n");
    printf("           -v  Verify the program is trusted or not\n");
    printf("           -h  Read helpful instruction\n");
}

char *strtrimr(char *pstr)
{
    int i;
    i = strlen(pstr) - 1;
    while (isspace(pstr[i]) && (i >= 0))
        pstr[i--] = '\0';
    return pstr;
}

char *strtriml(char *pstr)
{
    int i = 0,j;
    j = strlen(pstr) - 1;
    while (isspace(pstr[i]) && (i <= j))
        i++;
    if (0<i)
        strcpy(pstr, &pstr[i]);
    return pstr;
}

char *strtrim(char *pstr)
{
    char *p;
    p = strtrimr(pstr);
    return strtriml(p);
}


/*05.02  weekly*/
char *fd_calculate(char *filename, char *alg)
{
	FILE *fp;
	char md5_cmd[80] = {"/usr/bin/md5sum "};
	char sha256_cmd[80] = {"/usr/bin/sha256sum "};
	char md5[33];
	char sha256[65];
	char *new_cmd;
	char *target;

	if (strcmp(alg, "md5") == 0) {
		new_cmd = strcat(md5_cmd, filename);
		fp = popen(new_cmd, "r");
		fgets(md5, sizeof(md5), fp);
		pclose(fp);
		target = fd_encrypt(md5);
	} else if (strcmp(alg, "sha256") == 0) {
		new_cmd = strcat(sha256_cmd, filename);
		fp = popen(new_cmd, "r");
		fgets(sha256, sizeof(sha256), fp);
		pclose(fp);
		target = fd_encrypt(sha256);
	}
	return target;
}

void fd_write_conf(char *conf, char *buffer)
{
	int fd;

	fd = open(conf, O_WRONLY|O_CREAT|O_APPEND, 0644);
	write(fd, buffer, strlen(buffer));
	close(fd);
}

char *fd_read_conf(char *conf, int size)
{
	int fd;
	char *buffer;

	fd = open(conf, O_RDONLY);
	buffer = (char *)malloc(size);
        read(fd, buffer, size);
        close(fd);

	return buffer;
}

int fd_check_repeat(char *pattern, char *source, regmatch_t pmatch[])
{
	int status, i;
        int cflags = REG_EXTENDED;
        const size_t nmatch = 1;
        regex_t reg;

	regcomp(&reg, pattern, cflags);
	status = regexec(&reg, source, nmatch, pmatch, 0);
	regfree(&reg);

	return status;
}

int fd_get_filesize(char *filename)
{
	int size = -1;
	struct stat statbuff;  

	if (stat(filename, &statbuff) >= 0) {  
		size = statbuff.st_size;  
	} 

	return size;
}


void fd_write_bin_conf(char *filename, char *enc_md5, char *enc_sha256, char *bin_filename)
{
	int status;
	char *buffer;
	regmatch_t pmatch[1];
	int size;

	size = fd_get_filesize(bin_filename);  
	if (size > 0) {
		buffer = fd_read_conf(bin_filename, size);
		status = fd_check_repeat(filename, buffer, pmatch);
		if (status != 0) {
			fd_write_conf(bin_filename, filename);
			fd_write_conf(bin_filename, " ");
			fd_write_conf(bin_filename, enc_md5);
			fd_write_conf(bin_filename, " ");
			fd_write_conf(bin_filename, enc_sha256);
			fd_write_conf(bin_filename, "\n");
			printf("Add %s to %s\n", filename, bin_filename);
		} else {
			printf("In %s, %s is exist\n", bin_filename, filename);
		}
		free(buffer);
	} else {
		fd_write_conf(bin_filename, filename);
		fd_write_conf(bin_filename, " ");
		fd_write_conf(bin_filename, enc_md5);
		fd_write_conf(bin_filename, " ");
		fd_write_conf(bin_filename, enc_sha256);
		fd_write_conf(bin_filename, "\n");
		printf("Add %s to %s\n", filename, bin_filename);
	}
}

void fd_write_ldd(char *filename, char *map_filename, char *ldd_filename)
{

	FILE *fp;
        char ldd_cmd[80] = {"/usr/bin/ldd "};
        char ldd[4096];
        char *new_cmd = strcat(ldd_cmd, filename);
        char *ld_filename;
	char *enc_md5;
	char *enc_sha256;
	int ld_status, map_status;
	char *ld_buffer, *map_buffer;
	int ldd_filename_size, map_filename_size;
	char *map_content;

        int status, i;
        regmatch_t pmatch[1];
        char *pattern = "/[^\\s]*/\\w+([-.]\\w+)*([_.]\\w+)*.\\w+.[0-9]+";

        fp = popen(new_cmd, "r");
        while(fgets(ldd, sizeof(ldd), fp) != NULL) {
                status = fd_check_repeat(pattern, ldd, pmatch);
                if (status == 0) {
                        ld_filename = malloc(pmatch[0].rm_eo - pmatch[0].rm_so + 1);
                        for (i = pmatch[0].rm_so; i < pmatch[0].rm_eo; i++)
                                ld_filename[i - pmatch[0].rm_so] = ldd[i];
                        ld_filename[pmatch[0].rm_eo - pmatch[0].rm_so] = '\0';
                        //printf("Fd write:%s\n", ld_filename);
			enc_md5 = fd_calculate(ld_filename, "md5");
			enc_sha256 = fd_calculate(ld_filename, "sha256");

			ldd_filename_size = fd_get_filesize(ldd_filename);
			if (ldd_filename_size > 0) {
				ld_buffer = fd_read_conf(ldd_filename, ldd_filename_size);
				ld_status = fd_check_repeat(ld_filename, ld_buffer, pmatch);
				if (ld_status != 0) {
					fd_write_conf(ldd_filename, ld_filename);
					fd_write_conf(ldd_filename, " ");
					fd_write_conf(ldd_filename, enc_md5);
					fd_write_conf(ldd_filename, " ");
					fd_write_conf(ldd_filename, enc_sha256);
					fd_write_conf(ldd_filename, "\n");
					//printf("Add %s to %s\n", ld_filename, ldd_filename);
				}
                                else
                                {
					//printf("In %s, %s is exist\n", ldd_filename, ld_filename);
				}
				free(ld_buffer);
			} else {
				fd_write_conf(ldd_filename, ld_filename);
				fd_write_conf(ldd_filename, " ");
				fd_write_conf(ldd_filename, enc_md5);
				fd_write_conf(ldd_filename, " ");
				fd_write_conf(ldd_filename, enc_sha256);
				fd_write_conf(ldd_filename, "\n");
				//printf("Add %s to %s\n", ld_filename, ldd_filename);
			}
			map_filename_size = fd_get_filesize(map_filename);
			if (map_filename_size > 0) {
				map_buffer = fd_read_conf(map_filename, map_filename_size);
				map_content = (char *)malloc(strlen(filename) + strlen(ld_filename) + 2);
				memset(map_content, 0, strlen(filename) + strlen(ld_filename) + 2);
				map_content = strcat(map_content, filename);
				map_content = strcat(map_content, " ");
				map_content = strcat(map_content, ld_filename);
				map_status = fd_check_repeat(map_content, map_buffer, pmatch);
				if (map_status != 0) {
					fd_write_conf(map_filename, filename);
					fd_write_conf(map_filename, " ");
					fd_write_conf(map_filename, ld_filename);
					fd_write_conf(map_filename, "\n");
					//printf("Add %s %s to %s\n", filename, ld_filename, ldd_filename);
				} else
                                {
					//printf("In %s, %s %s is exist\n", map_filename, filename, ld_filename);
				}
				free(map_content);
				free(map_buffer);
			}
                        else 
                        {
				fd_write_conf(map_filename, filename);
				fd_write_conf(map_filename, " ");
				fd_write_conf(map_filename, ld_filename);
				fd_write_conf(map_filename, "\n");
				//printf("Add %s %s to %s\n", filename, ld_filename, ldd_filename);
			}
                        //printf("%s %s %s %s\n", filename, ld_filename, enc_md5, enc_sha256);
                        if( ld_filename != NULL)
                        {
                            free(ld_filename);
                        }
                }
        }
        pclose(fp);
}


HashInfo * getSohashinfo(char *filename)
{
        FILE *dbfp;
        char line[1024];
        HashInfo *info_tmp = (HashInfo *)malloc(sizeof(HashInfo));

        dbfp = fopen("/etc/mac_conf/trust_so_list", "r");
        if(dbfp == NULL)
                return NULL;
        if(!fgets(line, 1023, dbfp))
        {
            return NULL;
        }
        else
        {
            fseek(dbfp, 0, SEEK_SET);
            while (fgets(line, 1023, dbfp))
            {
               memset(info_tmp, 0, sizeof(HashInfo));
               int count = 0;
               char tmp[] = " ";
               char *str = NULL;
               str = strtok(line, tmp);
               while( str != NULL)
               {
                   if(count == 0)
                   {
                        strcpy(info_tmp->name, str);
                   }
                   else if(count == 1)
                   {
                         strcpy(info_tmp->enc_md5, str);
                   }
                   else if(count == 2)
                   {
                         strncpy(info_tmp->enc_sha256, str,sizeof(info_tmp->enc_sha256));
                   }
                   str = strtok(NULL, tmp);
                   count++;
               }
               int ret = strcmp(filename, info_tmp->name);
               if(ret == 0)
               {
                   return info_tmp;
               }
           }
       }
       fclose(dbfp);    
       if(info_tmp != NULL)
       {
           free(info_tmp);
       }
}

int check_lib_so(char *binprm)
{
        FILE *fp;
        char ldd_cmd[80] = {"/usr/bin/ldd "};
        char ldd[65536];
        char *new_cmd = strcat(ldd_cmd, binprm);
        char *ld_filename;
	char *enc_md5;
	char *enc_sha256;
	int ld_status, map_status;
	char *ld_buffer, *map_buffer;
	int ldd_filename_size, map_filename_size;
	char *map_content;
        int status, i;
        regmatch_t pmatch[1];
        char *pattern = "/[^\\s]*/\\w+([-.]\\w+)*([_.]\\w+)*.\\w+.[0-9]+";
        fp = popen(new_cmd, "r");
        while(fgets(ldd, sizeof(ldd), fp) != NULL)
	{
                status = fd_check_repeat(pattern, ldd, pmatch);
                if (status == 0)
                {
                        ld_filename = malloc(pmatch[0].rm_eo - pmatch[0].rm_so + 1);
                        for (i = pmatch[0].rm_so; i < pmatch[0].rm_eo; i++)
                                ld_filename[i - pmatch[0].rm_so] = ldd[i];
                        ld_filename[pmatch[0].rm_eo - pmatch[0].rm_so] = '\0';
                        //printf("Test:%s\n", ld_filename);
			enc_md5 = fd_calculate(ld_filename, "md5");
			enc_sha256 = fd_calculate(ld_filename, "sha256");
                        HashInfo *info_read = getSohashinfo(ld_filename);
                        if ( !info_read )
                        {
                            printf("The associated library check is not passed.\n");
                            return -1;
                        }
                        //printf("CreateInfo:%s %s %s\n", ld_filename, enc_md5, enc_sha256);
                        //printf("ReadDBInfo:%s %s %s\n", info_read->name, info_read->enc_md5, info_read->enc_sha256);
                        int md5_ret = strcmp(enc_md5, info_read->enc_md5);
                        int sha256_ret = strncmp(enc_sha256, info_read->enc_sha256, strlen(enc_sha256));
                        if((md5_ret != 0) || (sha256_ret != 0))
                        {
                            printf("The associated library check is not passed.\n");
                            return -1;
                        }
                 }
        }
}

