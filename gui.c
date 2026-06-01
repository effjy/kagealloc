#include <gtk/gtk.h>
#include <sys/wait.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <signal.h>

#define NUM_TESTS 3

typedef struct {
    int id;
    const char *name;
    const char *desc;
    const char *raw_arg;
    int expected_sig;
    
    // UI elements
    GtkWidget *card_box;
    GtkWidget *status_badge;
    GtkWidget *run_btn;
    GtkTextBuffer *log_buffer;
    GtkWidget *expander;
    
    GPid pid;
    gint stdout_fd;
} test_case_t;

static test_case_t tests[NUM_TESTS] = {
    {0, "Batched Key-Rotation (BKR)", "Enforces a hardware-backed memory quarantine on pages to prevent Use-After-Free (UAF) access.", "--raw-bkr", 11}, // SIGSEGV = 11
    {1, "Thread-Isolated Metadata Partitioning (TIMP)", "Isolates allocator metadata pages per thread, preventing cross-thread heap corruption.", "--raw-timp", 11}, // SIGSEGV = 11
    {2, "Register-Isolated Cryptographic Call Gates (RICCG)", "Encapsulates wrpkru updates in a call gate checking %r15, preventing ROP bypasses.", "--raw-riccg", 4} // SIGILL = 4
};

static GtkWidget *summary_label;
static GtkWidget *run_all_btn;
static int tests_passed_count = 0;
static int tests_completed_count = 0;

static const char *css_styles = 
"window {\n"
"    background-color: #0f172a;\n"
"    color: #f8fafc;\n"
"}\n"
".header {\n"
"    background: linear-gradient(135deg, #1e293b, #0f172a);\n"
"    border-bottom: 2px solid #334155;\n"
"    padding: 16px;\n"
"}\n"
".header-title {\n"
"    font-size: 20px;\n"
"    font-weight: bold;\n"
"    color: #38bdf8;\n"
"}\n"
".card {\n"
"    background-color: #1e293b;\n"
"    border-radius: 8px;\n"
"    border: 1px solid #334155;\n"
"    padding: 14px;\n"
"    margin: 8px 16px;\n"
"}\n"
".test-title {\n"
"    font-size: 15px;\n"
"    font-weight: bold;\n"
"    color: #ffffff;\n"
"}\n"
".test-desc {\n"
"    font-size: 12px;\n"
"    color: #94a3b8;\n"
"}\n"
".btn-run {\n"
"    background-color: #0284c7;\n"
"    color: white;\n"
"    font-weight: bold;\n"
"    border-radius: 6px;\n"
"    padding: 6px 14px;\n"
"    border: none;\n"
"}\n"
".btn-run:hover {\n"
"    background-color: #0369a1;\n"
"}\n"
".btn-run:disabled {\n"
"    background-color: #475569;\n"
"    color: #94a3b8;\n"
"}\n"
".btn-run-all {\n"
"    background-color: #10b981;\n"
"    color: white;\n"
"    font-weight: bold;\n"
"    border-radius: 6px;\n"
"    padding: 8px 16px;\n"
"    border: none;\n"
"}\n"
".btn-run-all:hover {\n"
"    background-color: #059669;\n"
"}\n"
".badge {\n"
"    font-weight: bold;\n"
"    font-size: 11px;\n"
"    border-radius: 12px;\n"
"    padding: 4px 10px;\n"
"}\n"
".badge-notrun {\n"
"    background-color: #475569;\n"
"    color: #cbd5e1;\n"
"}\n"
".badge-running {\n"
"    background-color: #d97706;\n"
"    color: #fef3c7;\n"
"}\n"
".badge-success {\n"
"    background-color: #059669;\n"
"    color: #ecfdf5;\n"
"}\n"
".badge-failure {\n"
"    background-color: #dc2626;\n"
"    color: #fef2f2;\n"
"}\n"
".log-view {\n"
"    font-family: 'Monospace', monospace;\n"
"    font-size: 11px;\n"
"    background-color: #020617;\n"
"    color: #e2e8f0;\n"
"}\n";

// Helper to set badge status
static void set_badge_status(GtkWidget *badge, const char *status_text, const char *status_class) {
    gtk_label_set_text(GTK_LABEL(badge), status_text);
    
    GtkStyleContext *context = gtk_widget_get_style_context(badge);
    
    // Remove existing classes
    gtk_style_context_remove_class(context, "badge-notrun");
    gtk_style_context_remove_class(context, "badge-running");
    gtk_style_context_remove_class(context, "badge-success");
    gtk_style_context_remove_class(context, "badge-failure");
    
    gtk_style_context_add_class(context, status_class);
}

// Global update for the header summary
static void update_summary_header(void) {
    char summary_text[128];
    if (tests_completed_count == 0) {
        sprintf(summary_text, "Status: Ready (0/%d executed)", NUM_TESTS);
    } else if (tests_completed_count < NUM_TESTS) {
        sprintf(summary_text, "Running: Executed %d/%d tests (%d passed)", 
                tests_completed_count, NUM_TESTS, tests_passed_count);
    } else {
        if (tests_passed_count == NUM_TESTS) {
            sprintf(summary_text, "Success: All %d/%d mitigations passed validation!", 
                    tests_passed_count, NUM_TESTS);
        } else {
            sprintf(summary_text, "Warning: Only %d/%d mitigations passed validation.", 
                    tests_passed_count, NUM_TESTS);
        }
    }
    gtk_label_set_text(GTK_LABEL(summary_label), summary_text);
}

// Callback when child process output is readable
static gboolean read_stdout_cb(GIOChannel *channel, GIOCondition cond, gpointer user_data) {
    test_case_t *tc = (test_case_t *)user_data;
    gchar buf[256];
    gsize bytes_read;
    GError *error = NULL;

    if (cond & G_IO_IN) {
        GIOStatus status = g_io_channel_read_chars(channel, buf, sizeof(buf) - 1, &bytes_read, &error);
        if (status == G_IO_STATUS_NORMAL && bytes_read > 0) {
            buf[bytes_read] = '\0';
            
            // Insert into TextView buffer
            GtkTextIter iter;
            gtk_text_buffer_get_end_iter(tc->log_buffer, &iter);
            gtk_text_buffer_insert(tc->log_buffer, &iter, buf, -1);
        }
    }

    if (cond & G_IO_HUP) {
        return FALSE; // Close the watch
    }

    return TRUE;
}

// Callback when child process terminates
static void child_watch_cb(GPid pid, gint status, gpointer user_data) {
    test_case_t *tc = (test_case_t *)user_data;
    
    g_spawn_close_pid(pid);
    tests_completed_count++;
    
    gchar log_msg[1024];
    GtkTextIter iter;

    if (WIFSIGNALED(status)) {
        int sig = WTERMSIG(status);
        
        char analysis[512] = "";
        if (sig == tc->expected_sig) {
            if (tc->id == 0) { // BKR
                sprintf(analysis, 
                    "ANALYSIS: The child process was successfully terminated by signal 11 (SIGSEGV).\n"
                    "This confirms that when the allocator rotated epochs and quarantined Pool 0,\n"
                    "its access was successfully disabled. Accessing the dangling pointer triggered\n"
                    "a hardware page-protection trap, successfully preventing the Use-After-Free access."
                );
            } else if (tc->id == 1) { // TIMP
                sprintf(analysis, 
                    "ANALYSIS: The child process was successfully terminated by signal 11 (SIGSEGV).\n"
                    "This confirms that when current thread attempted to modify the metadata page of\n"
                    "Thread 1, the hardware MMU blocked the write. Access was disabled in the current\n"
                    "thread's PKRU register, successfully preventing cross-thread metadata corruption."
                );
            } else if (tc->id == 2) { // RICCG
                sprintf(analysis, 
                    "ANALYSIS: The child process was successfully terminated by signal 4 (SIGILL).\n"
                    "This confirms that the call gate secure check verified the token in CPU register %%r15.\n"
                    "Since the ROP simulator passed an incorrect token, the gate executed the 'ud2'\n"
                    "instruction, halting execution and preventing unauthorized PKRU changes."
                );
            }
            
            set_badge_status(tc->status_badge, "SUCCESS (TRAPPED)", "badge-success");
            tests_passed_count++;
            
            sprintf(log_msg, 
                "\n------------------------------------------------------\n"
                "VERIFICATION RESULT: SUCCESS (TRAPPED)\n"
                "Child process terminated by signal %d (%s) as expected.\n"
                "%s\n"
                "======================================================\n",
                sig, strsignal(sig), analysis
            );
        } else {
            set_badge_status(tc->status_badge, "FAILED", "badge-failure");
            sprintf(log_msg, 
                "\n------------------------------------------------------\n"
                "VERIFICATION RESULT: FAILED\n"
                "Child process terminated by signal %d (%s), but expected signal %d.\n"
                "The mitigation did not trap the attack correctly.\n"
                "======================================================\n",
                sig, strsignal(sig), tc->expected_sig
            );
        }
    } else {
        int exit_code = WEXITSTATUS(status);
        set_badge_status(tc->status_badge, "FAILED", "badge-failure");
        sprintf(log_msg, 
            "\n------------------------------------------------------\n"
            "VERIFICATION RESULT: FAILED\n"
            "Child process completed normally with exit code %d.\n"
            "No hardware/kernel trap was triggered. The mitigation failed to block the exploit.\n"
            "======================================================\n",
            exit_code
        );
    }
    
    gtk_text_buffer_get_end_iter(tc->log_buffer, &iter);
    gtk_text_buffer_insert(tc->log_buffer, &iter, log_msg, -1);

    gtk_widget_set_sensitive(tc->run_btn, TRUE);
    gtk_widget_set_sensitive(run_all_btn, TRUE);
    
    // Auto-expand the expander to show logs on completion
    gtk_expander_set_expanded(GTK_EXPANDER(tc->expander), TRUE);
    
    update_summary_header();
}

// Function to trigger a single test
static void trigger_test(test_case_t *tc) {
    // Reset indicators
    set_badge_status(tc->status_badge, "RUNNING...", "badge-running");
    gtk_text_buffer_set_text(tc->log_buffer, "", 0);
    gtk_widget_set_sensitive(tc->run_btn, FALSE);
    gtk_widget_set_sensitive(run_all_btn, FALSE);

    // Print informative header in text view
    GtkTextIter iter;
    gtk_text_buffer_get_end_iter(tc->log_buffer, &iter);
    char header[1024];
    sprintf(header, 
        "======================================================\n"
        "TEST INITIATED: %s\n"
        "======================================================\n"
        "Target raw CLI argument: %s\n"
        "Expected termination signal: %d (%s)\n"
        "Description: %s\n"
        "------------------------------------------------------\n"
        "Spawning isolated child process and redirecting stdout...\n\n",
        tc->name, tc->raw_arg, tc->expected_sig, 
        (tc->expected_sig == 11) ? "SIGSEGV (Segmentation Fault)" : "SIGILL (Illegal Instruction)",
        tc->desc
    );
    gtk_text_buffer_insert(tc->log_buffer, &iter, header, -1);

    gchar *argv[] = { "./kagealloc_test", (gchar*)tc->raw_arg, NULL };
    GError *error = NULL;

    gboolean success = g_spawn_async_with_pipes(
        NULL,           // Working directory
        argv,           // Command argv
        NULL,           // Envp
        G_SPAWN_DO_NOT_REAP_CHILD,
        NULL,           // Child setup func
        NULL,           // Child setup data
        &tc->pid,       // GPid output
        NULL,           // stdin fd
        &tc->stdout_fd, // stdout fd
        NULL,           // stderr fd
        &error
    );

    if (!success) {
        set_badge_status(tc->status_badge, "SPAWN ERROR", "badge-failure");
        
        gtk_text_buffer_get_end_iter(tc->log_buffer, &iter);
        gtk_text_buffer_insert(tc->log_buffer, &iter, "Failed to spawn test binary. Ensure it is compiled!\n", -1);
        
        gtk_widget_set_sensitive(tc->run_btn, TRUE);
        gtk_widget_set_sensitive(run_all_btn, TRUE);
        return;
    }

    // Set up standard output redirection channel
    GIOChannel *channel = g_io_channel_unix_new(tc->stdout_fd);
    g_io_channel_set_encoding(channel, NULL, NULL);
    g_io_add_watch(channel, G_IO_IN | G_IO_HUP, (GIOFunc)read_stdout_cb, tc);

    // Watch child process exit
    g_child_watch_add(tc->pid, child_watch_cb, tc);
}

// GCallback for test execution
static void on_run_test_clicked(GtkWidget *widget, gpointer data) {
    test_case_t *tc = (test_case_t *)data;
    
    // Decrement from progress if re-running
    GtkStyleContext *ctx = gtk_widget_get_style_context(tc->status_badge);
    if (gtk_style_context_has_class(ctx, "badge-success")) {
        tests_passed_count--;
        tests_completed_count--;
    } else if (gtk_style_context_has_class(ctx, "badge-failure")) {
        tests_completed_count--;
    }
    
    trigger_test(tc);
}

// Run All handler
static void on_run_all_clicked(GtkWidget *widget, gpointer data) {
    tests_passed_count = 0;
    tests_completed_count = 0;
    
    update_summary_header();
    
    // Trigger BKR (which starts watch chain if done sequentially; here we trigger all concurrently)
    for (int i = 0; i < NUM_TESTS; i++) {
        trigger_test(&tests[i]);
    }
}

int main(int argc, char *argv[]) {
    gtk_init(&argc, &argv);

    // Load custom CSS styling
    GtkCssProvider *css_provider = gtk_css_provider_new();
    gtk_css_provider_load_from_data(css_provider, css_styles, -1, NULL);
    gtk_style_context_add_provider_for_screen(
        gdk_screen_get_default(),
        GTK_STYLE_PROVIDER(css_provider),
        GTK_STYLE_PROVIDER_PRIORITY_APPLICATION
    );

    // Main window setup
    GtkWidget *window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window), "KageAlloc Mitigation Dashboard");
    gtk_window_set_default_size(GTK_WINDOW(window), 700, 680);
    gtk_window_set_resizable(GTK_WINDOW(window), TRUE);
    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    // Main vertical box layout
    GtkWidget *main_layout = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_container_add(GTK_CONTAINER(window), main_layout);

    // Header panel setup
    GtkWidget *header_bar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    gtk_widget_set_name(header_bar, "header_panel");
    gtk_style_context_add_class(gtk_widget_get_style_context(header_bar), "header");
    gtk_box_pack_start(GTK_BOX(main_layout), header_bar, FALSE, FALSE, 0);

    GtkWidget *header_title_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
    gtk_box_pack_start(GTK_BOX(header_bar), header_title_box, TRUE, TRUE, 0);

    GtkWidget *title_lbl = gtk_label_new("KageAlloc Security Dashboard");
    gtk_widget_set_halign(title_lbl, GTK_ALIGN_START);
    gtk_style_context_add_class(gtk_widget_get_style_context(title_lbl), "header-title");
    gtk_box_pack_start(GTK_BOX(header_title_box), title_lbl, FALSE, FALSE, 0);

    summary_label = gtk_label_new("Status: Ready (0/3 executed)");
    gtk_widget_set_halign(summary_label, GTK_ALIGN_START);
    gtk_style_context_add_class(gtk_widget_get_style_context(summary_label), "test-desc");
    gtk_box_pack_start(GTK_BOX(header_title_box), summary_label, FALSE, FALSE, 0);

    run_all_btn = gtk_button_new_with_label("Run All Tests");
    gtk_style_context_add_class(gtk_widget_get_style_context(run_all_btn), "btn-run-all");
    gtk_widget_set_valign(run_all_btn, GTK_ALIGN_CENTER);
    g_signal_connect(run_all_btn, "clicked", G_CALLBACK(on_run_all_clicked), NULL);
    gtk_box_pack_end(GTK_BOX(header_bar), run_all_btn, FALSE, FALSE, 0);

    // Scrolled window to hold tests container
    GtkWidget *scroll_content = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll_content), GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_box_pack_start(GTK_BOX(main_layout), scroll_content, TRUE, TRUE, 0);

    GtkWidget *tests_list_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_container_add(GTK_CONTAINER(scroll_content), tests_list_box);

    // Construct test cards
    for (int i = 0; i < NUM_TESTS; i++) {
        test_case_t *tc = &tests[i];

        tc->card_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
        gtk_style_context_add_class(gtk_widget_get_style_context(tc->card_box), "card");
        gtk_box_pack_start(GTK_BOX(tests_list_box), tc->card_box, FALSE, FALSE, 0);

        // Card Top Row Info
        GtkWidget *top_row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
        gtk_box_pack_start(GTK_BOX(tc->card_box), top_row, FALSE, FALSE, 0);

        GtkWidget *text_details = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
        gtk_box_pack_start(GTK_BOX(top_row), text_details, TRUE, TRUE, 0);

        GtkWidget *name_lbl = gtk_label_new(tc->name);
        gtk_widget_set_halign(name_lbl, GTK_ALIGN_START);
        gtk_style_context_add_class(gtk_widget_get_style_context(name_lbl), "test-title");
        gtk_box_pack_start(GTK_BOX(text_details), name_lbl, FALSE, FALSE, 0);

        GtkWidget *desc_lbl = gtk_label_new(tc->desc);
        gtk_label_set_line_wrap(GTK_LABEL(desc_lbl), TRUE);
        gtk_widget_set_halign(desc_lbl, GTK_ALIGN_START);
        gtk_style_context_add_class(gtk_widget_get_style_context(desc_lbl), "test-desc");
        gtk_box_pack_start(GTK_BOX(text_details), desc_lbl, FALSE, FALSE, 0);

        tc->status_badge = gtk_label_new("NOT RUN");
        gtk_style_context_add_class(gtk_widget_get_style_context(tc->status_badge), "badge");
        gtk_style_context_add_class(gtk_widget_get_style_context(tc->status_badge), "badge-notrun");
        gtk_widget_set_valign(tc->status_badge, GTK_ALIGN_CENTER);
        gtk_box_pack_start(GTK_BOX(top_row), tc->status_badge, FALSE, FALSE, 0);

        tc->run_btn = gtk_button_new_with_label("Run");
        gtk_style_context_add_class(gtk_widget_get_style_context(tc->run_btn), "btn-run");
        gtk_widget_set_valign(tc->run_btn, GTK_ALIGN_CENTER);
        g_signal_connect(tc->run_btn, "clicked", G_CALLBACK(on_run_test_clicked), tc);
        gtk_box_pack_start(GTK_BOX(top_row), tc->run_btn, FALSE, FALSE, 0);

        // Terminal Log Expander
        tc->expander = gtk_expander_new("View console trace logs");
        gtk_box_pack_start(GTK_BOX(tc->card_box), tc->expander, FALSE, FALSE, 0);

        GtkWidget *log_scrolled = gtk_scrolled_window_new(NULL, NULL);
        gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(log_scrolled), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
        gtk_widget_set_size_request(log_scrolled, -1, 140);
        gtk_container_add(GTK_CONTAINER(tc->expander), log_scrolled);

        GtkWidget *log_view = gtk_text_view_new();
        gtk_text_view_set_editable(GTK_TEXT_VIEW(log_view), FALSE);
        gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(log_view), FALSE);
        gtk_style_context_add_class(gtk_widget_get_style_context(log_view), "log-view");
        tc->log_buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(log_view));
        gtk_container_add(GTK_CONTAINER(log_scrolled), log_view);
    }

    gtk_widget_show_all(window);
    gtk_main();

    return 0;
}
