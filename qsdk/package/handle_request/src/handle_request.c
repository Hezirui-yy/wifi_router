#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <json-c/json.h>

#define MAX_QUERY_LENGTH 1024
#define MAX_BUFFER 1024

// Function prototypes
void handle_post_request();
void handle_get_request() {
    printf("{\"message\":\"GET request handled\"}\n");
}

void execute_command(const char *command, char *output, size_t max_size);

char *json_get_string_value_by_field(struct json_object *json, const char *p_field) {
    struct json_object *string_json = NULL;

    json_object_object_get_ex(json, p_field, &string_json);
    if (NULL == string_json) {
        return NULL;
    }

    if (json_type_string == json_object_get_type(string_json)) {
        return (char *)json_object_get_string(string_json);
    }

    return NULL;
}

int json_get_int_value_by_field(struct json_object *json, const char *p_field) {
    struct json_object *int_json = NULL;

    json_object_object_get_ex(json, p_field, &int_json);
    if (NULL == int_json) {
        return -1;
    }

    if (json_type_int == json_object_get_type(int_json)) {
        return json_object_get_int(int_json);
    }

    return -1;
}

const char *json_get_string_value(struct json_object *json) {
    if (json_type_string == json_object_get_type(json)) {
        return json_object_get_string(json);
    }

    return NULL;
}

struct json_object *json_get_json_object_by_field(struct json_object *json, const char *p_field) {
    struct json_object *json_obj = NULL;

    json_object_object_get_ex(json, p_field, &json_obj);
    return json_obj;
}

int json_is_array(struct json_object *json) {
    return (json_type_array == json_object_get_type(json)) ? 0 : -1;
}

void execute_command(const char *command, char *output, size_t max_size) {
    FILE *fp;
    char buffer[MAX_BUFFER];
    size_t current_size = 0;
    if (output) {
	memset(output, 0, max_size);
    }
    fp = popen(command, "r");
    if (fp == NULL) {
        perror("popen failed");
        output[0] = '\0';
        return;
    }
    while (fgets(buffer, sizeof(buffer) - 1, fp) != NULL) {
        size_t len = strlen(buffer);
        if (current_size + len < max_size - 1) {
            strcpy(output + current_size, buffer);
            current_size += len;
        }else{
             break;
	}
    }
    output[current_size] = '\0'; // Ensure null termination
    if (pclose(fp) == -1) {
        perror("pclose failed");
    }
}

void handle_post_request() {
    char query[MAX_QUERY_LENGTH];
    size_t content_length;
    char *content_length_str = getenv("CONTENT_LENGTH");

    if (content_length_str == NULL) {
        fprintf(stderr, "Error: CONTENT_LENGTH not set\n");
        printf("{\"error\":1,\"message\":\"Missing CONTENT_LENGTH\"}\n");
        return;
    }

    content_length = (size_t)atoi(content_length_str);
    if (content_length >= MAX_QUERY_LENGTH) {
        fprintf(stderr, "Error: Content length %zu exceeds maximum %d\n", content_length, MAX_QUERY_LENGTH);
        printf("{\"error\":1,\"message\":\"Request too large\"}\n");
        return;
    }

    // Read POST data
    size_t bytes_read = fread(query, 1, content_length, stdin);
    if (bytes_read != content_length) {
        fprintf(stderr, "Error: Expected %zu bytes, read %zu bytes\n", content_length, bytes_read);
        printf("{\"error\":1,\"message\":\"Failed to read POST data\"}\n");
        return;
    }
    query[content_length] = '\0'; // Null-terminate

    // Parse JSON
    struct json_object *myjson = json_tokener_parse(query);
    if (myjson == NULL) {
        fprintf(stderr, "Error: Invalid JSON\n");
        printf("{\"error\":1,\"message\":\"Invalid JSON\"}\n");
        return;
    }

    char *action = json_get_string_value_by_field(myjson, "ACT");
    if (action == NULL) {
        fprintf(stderr, "Error: Missing action field\n");
        printf("{\"error\":1,\"message\":\"Missing action\"}\n");
        json_object_put(myjson);
        return;
    }

    if (strcmp(action, "Login") == 0) {
        struct json_object *param = json_get_json_object_by_field(myjson, "param");
        if (param == NULL) {
            fprintf(stderr, "Error: Missing parameters\n");
            printf("{\"error\":1,\"message\":\"Missing parameters\"}\n");
            json_object_put(myjson);
            return;
        }

        char *admin = json_get_string_value_by_field(param, "admin");
        char *pwd = json_get_string_value_by_field(param, "pwd");

        if (admin && pwd && strcmp(admin, "admin") == 0 && strcmp(pwd, "123456") == 0) {
            printf("{\"error\":0}\n");
        } else {
            printf("{\"error\":1,\"message\":\"admin or pwd error\"}\n");
        }
        json_object_put(param);
    }else if(strcmp(action, "GetVersion")==0){
	char version_info[MAX_BUFFER] = {0};
        char line[MAX_BUFFER] = {0};
        execute_command("cat /etc/system_version.info", version_info, MAX_BUFFER);
        struct json_object *response = json_object_new_object();
	struct json_object *version_obj = json_object_new_object();
    	char *line_start = version_info;
        while (sscanf(line_start, "%[^\n]\n", line) == 1) {
		char *key_end = strchr(line, '=');
		if (key_end) {
		    *key_end = '\0';
		    char *value_start = key_end + 1;
		    if (*value_start == '"') {
		        value_start++;
		    }
		    char *value_end = strchr(value_start, '"');
		    if (value_end) {
		        *value_end = '\0';
		    }
		    json_object_object_add(version_obj, line, json_object_new_string(value_start));
		}
		line_start = strchr(line_start, '\n');
		if (line_start) {
		    line_start++;
		}
    	}
        json_object_object_add(response, "version_info", version_obj);
	printf("\n");
        json_object_object_add(response, "error", json_object_new_int(0));
        printf("%s\n", json_object_to_json_string(response));
        json_object_put(response);
    }else if(strcmp(action,"GetWifi") == 0){
	char wifi_device[MAX_BUFFER] = {0};
        char wifi_network[MAX_BUFFER] = {0};
        char wifi_mode[MAX_BUFFER] = {0};
        char wifi_ssid[MAX_BUFFER] = {0};
        char wifi_encryption[MAX_BUFFER] = {0};
	char wifi_key[MAX_BUFFER] = {0};
        execute_command("uci get wireless.wla.device", wifi_device, MAX_BUFFER);
        execute_command("uci get wireless.wla.network",wifi_network , MAX_BUFFER);
        execute_command("uci get wireless.wla.mode", wifi_mode, MAX_BUFFER);
        execute_command("uci get wireless.wla.ssid", wifi_ssid, MAX_BUFFER);
        execute_command("uci get wireless.wla.encryption", wifi_encryption, MAX_BUFFER);
	execute_command("uci get wireless.wla.key", wifi_key, MAX_BUFFER);

	struct json_object *response = json_object_new_object();
	json_object_object_add(response, "wifi_device", json_object_new_string(wifi_device));
        json_object_object_add(response, "wifi_network", json_object_new_string(wifi_network));
        json_object_object_add(response, "wifi_mode", json_object_new_string(wifi_mode));
        json_object_object_add(response, "wifi_ssid", json_object_new_string(wifi_ssid));
        json_object_object_add(response, "wifi_encryption", json_object_new_string(wifi_encryption));
	json_object_object_add(response, "wifi_key", json_object_new_string(wifi_key));
        json_object_object_add(response, "error", json_object_new_int(0)); 
        
        printf("%s\n", json_object_to_json_string(response));
        json_object_put(response);
    } else if (strcmp(action, "GetDHCP") == 0) {
        char ipaddr[MAX_BUFFER] = {0};
        char netmask[MAX_BUFFER] = {0};
        char start[MAX_BUFFER] = {0};
        char limit[MAX_BUFFER] = {0};
        char leasetime[MAX_BUFFER] = {0};
        execute_command("uci get network.lan.ipaddr", ipaddr, MAX_BUFFER);
        execute_command("uci get network.lan.netmask", netmask, MAX_BUFFER);
        execute_command("uci get dhcp.lan.start", start, MAX_BUFFER);
        execute_command("uci get dhcp.lan.limit", limit, MAX_BUFFER);
        execute_command("uci get dhcp.lan.leasetime", leasetime, MAX_BUFFER);
        
        struct json_object *response = json_object_new_object();
        json_object_object_add(response, "ipaddr", json_object_new_string(ipaddr));
        json_object_object_add(response, "netmask", json_object_new_string(netmask));
        json_object_object_add(response, "start", json_object_new_string(start));
        json_object_object_add(response, "limit", json_object_new_string(limit));
        json_object_object_add(response, "leasetime", json_object_new_string(leasetime));
        json_object_object_add(response, "error", json_object_new_int(0)); 
        
        printf("%s\n", json_object_to_json_string(response));
        json_object_put(response);
    }else if(strcmp("SetDHCP",action)==0){
        char cmd[512]={0};
        int error=0;
        char *ipaddr=json_get_string_value_by_field(myjson, "ipaddr");
        if(ipaddr){
            error=1;
        }
        char *netmask=json_get_string_value_by_field(myjson,"netmask");
        if(netmask){
            error=1;
        }
        char *start=json_get_string_value_by_field(myjson,"start");
        if(start){
            error=1;
        }
        char *limit=json_get_string_value_by_field(myjson,"limit");
        if(limit){
            error=1;
        }
        char *leasetime=json_get_string_value_by_field(myjson,"leasetime");
        if(leasetime){
            error=1;
        }
        //uci set network.lan.ipaddr xx
        sprintf(cmd,"uci set network.lan.ipaddr %s",ipaddr);
        system(cmd);
        
        memset(cmd,0,512);
        sprintf(cmd,"uci set network.lan.netmask %s",netmask);
        system(cmd);
        
        memset(cmd,0,512);
        sprintf(cmd,"uci set network.lan.start %s",start);
        system(cmd);
        
        memset(cmd,0,512);
        sprintf(cmd,"uci set network.lan.limit %s",limit);
        system(cmd);
        
        memset(cmd,0,512);
        sprintf(cmd,"uci set network.lan.leasetime %s",leasetime);
        system(cmd);
        
        system("uci commit");
        system("/etc/init.d/network restart");
        
        printf("{\"error\":%dl\n",error);
    }else if(strcmp(action,"SetWifi")==0){
        char cmd[512]={0};
        int error=0;
        char *wifi_device=json_get_string_value_by_field(myjson,"wifi_device");
        if(wifi_device){
            error=1;
        }
        char *wifi_ssid=json_get_string_value_by_field(myjson,"wifi_ssid");
        if(wifi_ssid){
            error=1;
        }
        memset(cmd,0,512);
        sprintf(cmd,"uci get wireless.wla.device=%s",wifi_device);
        system(cmd);
        
        memset(cmd,0,512);
        sprintf(cmd,"uci get wireless.wla.ssid=%s",wifi_ssid);
        system(cmd);
        
        system("uci commit wireless");
        system("/etc/init.d/wireless restart");
        
        printf("{\"error\":%d\n",error);
    }else{
        fprintf(stderr, "Error: Unknown action %s\n",action);
        printf("{\"error\":1,\"message\":\"Unknown action\"}\n");
    }
    json_object_put(myjson);
}

int main() {
    const char *method = getenv("REQUEST_METHOD");

    printf("Content-Type: application/json\n\n");

    if (method != NULL && strcmp(method, "POST") == 0) {
        handle_post_request();
    } else if (method != NULL && strcmp(method, "GET") == 0) {
        handle_get_request(); // Implement if needed
    } else {
        printf("{\"error\":1,\"message\":\"Method not supported\"}\n");
    }

    return 0;
}

