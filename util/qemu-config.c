#include "qemu-common.h"
#include "qemu/error-report.h"
#include "qemu/option.h"
#include "qemu/config-file.h"
#include "qapi/qmp/qerror.h"
#include "hw/qdev.h"
#include "qapi/error.h"
#include "qmp-commands.h"

static QemuOptsList *vm_config_groups[32];
static QemuOptsList *drive_config_groups[4];

static QemuOptsList *find_list(QemuOptsList **lists, const char *group,
                               Error **errp)
{
    int i;

    for (i = 0; lists[i] != NULL; i++) {
        if (strcmp(lists[i]->name, group) == 0)
            break;
    }
    if (lists[i] == NULL) {
        error_set(errp, QERR_INVALID_OPTION_GROUP, group);
    }
    return lists[i];
}

QemuOptsList *qemu_find_opts(const char *group)
{
    QemuOptsList *ret;
    Error *local_err = NULL;

    ret = find_list(vm_config_groups, group, &local_err);
    if (error_is_set(&local_err)) {
        error_report("%s", error_get_pretty(local_err));
        error_free(local_err);
    }

    return ret;
}

static CommandLineParameterInfoList *query_option_descs(const QemuOptDesc *desc)
{
    CommandLineParameterInfoList *param_list = NULL, *entry;
    CommandLineParameterInfo *info;
    int i;

    for (i = 0; desc[i].name != NULL; i++) {
        info = g_malloc0(sizeof(*info));
        info->name = g_strdup(desc[i].name);

        switch (desc[i].type) {
        case QEMU_OPT_STRING:
            info->type = COMMAND_LINE_PARAMETER_TYPE_STRING;
            break;
        case QEMU_OPT_BOOL:
            info->type = COMMAND_LINE_PARAMETER_TYPE_BOOLEAN;
            break;
        case QEMU_OPT_NUMBER:
            info->type = COMMAND_LINE_PARAMETER_TYPE_NUMBER;
            break;
        case QEMU_OPT_SIZE:
            info->type = COMMAND_LINE_PARAMETER_TYPE_SIZE;
            break;
        }

        if (desc[i].help) {
            info->has_help = true;
            info->help = g_strdup(desc[i].help);
        }

        entry = g_malloc0(sizeof(*entry));
        entry->value = info;
        entry->next = param_list;
        param_list = entry;
    }

    return param_list;
}

/* remove repeated entry from the info list */
static void cleanup_infolist(CommandLineParameterInfoList *head)
{
    CommandLineParameterInfoList *pre_entry, *cur, *del_entry;

    cur = head;
    while (cur->next) {
        pre_entry = head;
        while (pre_entry != cur->next) {
            if (!strcmp(pre_entry->value->name, cur->next->value->name)) {
                del_entry = cur->next;
                cur->next = cur->next->next;
                g_free(del_entry);
                break;
            }
            pre_entry = pre_entry->next;
        }
        cur = cur->next;
    }
}

/* merge the description items of two parameter infolists */
static void connect_infolist(CommandLineParameterInfoList *head,
                             CommandLineParameterInfoList *new)
{
    CommandLineParameterInfoList *cur;

    cur = head;
    while (cur->next) {
        cur = cur->next;
    }
    cur->next = new;
}

/* access all the local QemuOptsLists for drive option */
static CommandLineParameterInfoList *get_drive_infolist(void)
{
    CommandLineParameterInfoList *head = NULL, *cur;
    int i;

    for (i = 0; drive_config_groups[i] != NULL; i++) {
        if (!head) {
            head = query_option_descs(drive_config_groups[i]->desc);
        } else {
            cur = query_option_descs(drive_config_groups[i]->desc);
            connect_infolist(head, cur);
        }
    }
    cleanup_infolist(head);

    return head;
}

CommandLineOptionInfoList *qmp_query_command_line_options(bool has_option,
                                                          const char *option,
                                                          Error **errp)
{
    CommandLineOptionInfoList *conf_list = NULL, *entry;
    CommandLineOptionInfo *info;
    int i;

    for (i = 0; vm_config_groups[i] != NULL; i++) {
        if (!has_option || !strcmp(option, vm_config_groups[i]->name)) {
            info = g_malloc0(sizeof(*info));
            info->option = g_strdup(vm_config_groups[i]->name);
            if (!strcmp("drive", vm_config_groups[i]->name)) {
                info->parameters = get_drive_infolist();
            } else {
                info->parameters =
                    query_option_descs(vm_config_groups[i]->desc);
            }
            entry = g_malloc0(sizeof(*entry));
            entry->value = info;
            entry->next = conf_list;
            conf_list = entry;
        }
    }

    if (conf_list == NULL) {
        error_setg(errp, "invalid option name: %s", option);
    }

    return conf_list;
}

QemuOptsList *qemu_find_opts_err(const char *group, Error **errp)
{
    return find_list(vm_config_groups, group, errp);
}

void qemu_add_drive_opts(QemuOptsList *list)
{
    int entries, i;

    entries = ARRAY_SIZE(drive_config_groups);
    entries--; /* keep list NULL terminated */
    for (i = 0; i < entries; i++) {
        if (drive_config_groups[i] == NULL) {
            drive_config_groups[i] = list;
            return;
        }
    }
    fprintf(stderr, "ran out of space in drive_config_groups");
    abort();
}

void qemu_add_opts(QemuOptsList *list)
{
    int entries, i;

    entries = ARRAY_SIZE(vm_config_groups);
    entries--; /* keep list NULL terminated */
    for (i = 0; i < entries; i++) {
        if (vm_config_groups[i] == NULL) {
            vm_config_groups[i] = list;
            return;
        }
    }
    fprintf(stderr, "ran out of space in vm_config_groups");
    abort();
}

int qemu_set_option(const char *str)
{
    char group[64], id[64], arg[64];
    QemuOptsList *list;
    QemuOpts *opts;
    int rc, offset;

    rc = sscanf(str, "%63[^.].%63[^.].%63[^=]%n", group, id, arg, &offset);
    if (rc < 3 || str[offset] != '=') {
        error_report("can't parse: \"%s\"", str);
        return -1;
    }

    list = qemu_find_opts(group);
    if (list == NULL) {
        return -1;
    }

    opts = qemu_opts_find(list, id);
    if (!opts) {
        error_report("there is no %s \"%s\" defined",
                     list->name, id);
        return -1;
    }

    if (qemu_opt_set(opts, arg, str+offset+1) == -1) {
        return -1;
    }
    return 0;
}

struct ConfigWriteData {
    QemuOptsList *list;
    FILE *fp;
};

static int config_write_opt(const char *name, const char *value, void *opaque)
{
    struct ConfigWriteData *data = opaque;

    fprintf(data->fp, "  %s = \"%s\"\n", name, value);
    return 0;
}

static int config_write_opts(QemuOpts *opts, void *opaque)
{
    struct ConfigWriteData *data = opaque;
    const char *id = qemu_opts_id(opts);

    if (id) {
        fprintf(data->fp, "[%s \"%s\"]\n", data->list->name, id);
    } else {
        fprintf(data->fp, "[%s]\n", data->list->name);
    }
    qemu_opt_foreach(opts, config_write_opt, data, 0);
    fprintf(data->fp, "\n");
    return 0;
}

void qemu_config_write(FILE *fp)
{
    struct ConfigWriteData data = { .fp = fp };
    QemuOptsList **lists = vm_config_groups;
    int i;

    fprintf(fp, "# qemu config file\n\n");
    for (i = 0; lists[i] != NULL; i++) {
        data.list = lists[i];
        qemu_opts_foreach(data.list, config_write_opts, &data, 0);
    }
}

int qemu_config_parse(FILE *fp, QemuOptsList **lists, const char *fname)
{
    char line[1024], group[64], id[64], arg[64], value[1024];
    Location loc;
    QemuOptsList *list = NULL;
    Error *local_err = NULL;
    QemuOpts *opts = NULL;
    int res = -1, lno = 0;

    loc_push_none(&loc);
    while (fgets(line, sizeof(line), fp) != NULL) {
        loc_set_file(fname, ++lno);
        if (line[0] == '\n') {
            /* skip empty lines */
            continue;
        }
        if (line[0] == '#') {
            /* comment */
            continue;
        }
        if (sscanf(line, "[%63s \"%63[^\"]\"]", group, id) == 2) {
            /* group with id */
            list = find_list(lists, group, &local_err);
            if (error_is_set(&local_err)) {
                error_report("%s", error_get_pretty(local_err));
                error_free(local_err);
                goto out;
            }
            opts = qemu_opts_create(list, id, 1, NULL);
            continue;
        }
        if (sscanf(line, "[%63[^]]]", group) == 1) {
            /* group without id */
            list = find_list(lists, group, &local_err);
            if (error_is_set(&local_err)) {
                error_report("%s", error_get_pretty(local_err));
                error_free(local_err);
                goto out;
            }
            opts = qemu_opts_create(list, NULL, 0, &error_abort);
            continue;
        }
        if (sscanf(line, " %63s = \"%1023[^\"]\"", arg, value) == 2) {
            /* arg = value */
            if (opts == NULL) {
                error_report("no group defined");
                goto out;
            }
            if (qemu_opt_set(opts, arg, value) != 0) {
                goto out;
            }
            continue;
        }
        error_report("parse error");
        goto out;
    }
    if (ferror(fp)) {
        error_report("error reading file");
        goto out;
    }
    res = 0;
out:
    loc_pop(&loc);
    return res;
}

int qemu_read_config_file(const char *filename)
{
    FILE *f = fopen(filename, "r");
    int ret;

    if (f == NULL) {
        return -errno;
    }

    ret = qemu_config_parse(f, vm_config_groups, filename);
    fclose(f);

    if (ret == 0) {
        return 0;
    } else {
        return -EINVAL;
    }
}
