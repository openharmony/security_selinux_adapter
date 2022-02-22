/* Copyright (c) 2021 北京万里红科技有限公司
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <selinux/selinux.h>
#include <securec.h>
#include <unistd.h>

#define BUFFLEN (1000)

int OpenFile(char *file)
{
    FILE *fp = NULL;
    char buf[BUFFLEN];

    fp = fopen(file, "r");
    if (fp != NULL) {
        if (memset_s(buf, sizeof(buf), 0, BUFFLEN) != 0) {
            fclose(fp);
            return 0;
        }

        fread(buf, 1, BUFFLEN, fp);
        fclose(fp);
        printf("buf %s\n", buf);
    }

    return 0;
}

int main(int argc, char *argv[])
{
    const int sleepSeconds = 1;
    char *files[] = {
        "/data/abcd.txt",
        "/data/abcd2.txt",
        "/data/abcd3.txt",
        NULL
    };
    int ret = 0;

    ret = setcon("u:r:kernel:s0");
    printf("setcon %d\n", ret);
    ret = setexeccon("u:r:kernel:s0");
    printf("setexeccon %d\n", ret);

    while (1) {
        for (int i = 0; files[i] != NULL; i++) {
            sleep(sleepSeconds);
            OpenFile(files[i]);
        }
    }

    return 0;
}
