#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <json-c/json.h>

#define MAX_QUERY_LENGTH 1024

// Function prototypes
void handle_post_request();

char *json_get_string_value_by_field(struct json_object *json, const char *p_field)
{
    struct json_object *string_json = NULL;

    json_object_object_get_ex(json, p_field, &string_json);
    if (NULL == string_json)
    {
        printf("json_object_object_get error %s\n", p_field);
        return NULL;
    }

    if (json_type_string == json_object_get_type(string_json))
    {
        return (char *)json_object_get_string(string_json);
    }

    return NULL;
}

int json_get_int_value_by_field(struct json_object *json, const char *p_field)
{
    struct json_object *int_json = NULL;

    json_object_object_get_ex(json, p_field, &int_json);
    if (NULL == int_json)
    {
        printf("json_object_object_get error %s\n", p_field);
        return -1;
    }

    if (json_type_int == json_object_get_type(int_json))
    {
        return json_object_get_int(int_json);
    }

    return -1;
}

const char *json_get_string_value(struct json_object *json)
{
    if (json_type_string == json_object_get_type(json))
    {
        return json_object_get_string(json);
    }

    return NULL;
}

struct json_object *json_get_json_object_by_field(struct json_object *json, const char *p_field)
{
    struct json_object *json_obj = NULL;

    json_object_object_get_ex(json, p_field, &json_obj);
    if (NULL == json_obj)
    {
        printf("json_object_object_get error %s\n", p_field);
        return NULL;
    }

    return json_obj;
}

int json_is_array(struct json_object *json)
{
    return (json_type_array == json_object_get_type(json)) ? 0 : -1;
}

void handle_post_request() {
    char query[MAX_QUERY_LENGTH];
    size_t content_length;
    char *content_length_str = getenv("CONTENT_LENGTH");

    if (content_length_str == NULL) {
        printf("{\"error\":1,\"message\":\"Missing CONTENT_LENGTH\"}\n");
        return;
    }

    content_length = (size_t)atoi(content_length_str);
    if (content_length >= MAX_QUERY_LENGTH) {
        printf("{\"error\":1,\"message\":\"Request too large\"}\n");
        return;
    }

    // Read POST data
    fread(query, 1, content_length, stdin);
    query[content_length] = '\0'; // Null-terminate
    
    // Parse JSON
    struct json_object *myjson = json_tokener_parse(query);
    if (myjson == NULL) {
        printf("{\"error\":1,\"message\":\"Invalid JSON\"}\n");
        return;
    }

    char *action = json_get_string_value_by_field(myjson, "ACT");
    if (action == NULL) {
        printf("{\"error\":1,\"message\":\"Missing action\"}\n");
        json_object_put(myjson);
        return;
    }

    if (strcmp(action, "Login") == 0) {
        struct json_object *param = json_get_json_object_by_field(myjson, "param");
        if (param == NULL) {
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
    } else if (strcmp(action, "dhcp") == 0) {
        // Handle DHCP action
        printf("{\"error\":0,\"message\":\"DHCP action not implemented\"}\n");
    } else {
        printf("{\"error\":1,\"message\":\"Unknown action\"}\n");
    }

    json_object_put(myjson);
}

int main() {
    // Check request method
    const char *method = getenv("REQUEST_METHOD");

    // Print HTTP header
    printf("Content-Type: application/json\n\n");

    if (method != NULL && strcmp(method, "POST") == 0) {
        handle_post_request();
    } else if (method != NULL && strcmp(method, "GET") == 0) {
        // handle_get_request(); // Implement if needed
    } else {
        // Method not supported
        printf("{\"error\":1,\"message\":\"Method not supported\"}\n");
    }

    return 0;
}

