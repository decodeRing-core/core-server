package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"text/tabwriter"

	"github.com/spf13/cobra"
)

var skipVerify bool

var rootCmd = &cobra.Command{
	Use:   "dcdr",
	Short: "A client for the dcdr server",
	Long:  `A client for the dcdr server`,
}

func init() {
	rootCmd.PersistentFlags().BoolVar(&skipVerify, "skip-verify", false, "Skip SSL certificate verification")

	rootCmd.AddCommand(identCmd)
	rootCmd.AddCommand(authCmd)
	rootCmd.AddCommand(registerCmd)
	rootCmd.AddCommand(createCmd)
	rootCmd.AddCommand(getCmd)
	rootCmd.AddCommand(taintCmd)
	rootCmd.AddCommand(untaintCmd)
	rootCmd.AddCommand(destroyCmd)
	rootCmd.AddCommand(isTaintedCmd)
	rootCmd.AddCommand(listAppsCmd)
	rootCmd.AddCommand(listSecretsCmd)
	rootCmd.AddCommand(listBackendsCmd)
	rootCmd.AddCommand(deleteAppCmd)
	rootCmd.AddCommand(appUserCmd)
	rootCmd.AddCommand(logoutCmd)
	rootCmd.AddCommand(whoamiCmd)
	rootCmd.AddCommand(downloadAuditLogsCmd)
}

var deleteAppCmd = &cobra.Command{
	Use:   "delete-app",
	Short: "Delete an application",
	Run: func(cmd *cobra.Command, args []string) {
		appID, _ := cmd.Flags().GetString("appid")
		doDeleteApp(appID)
	},
}

var listBackendsCmd = &cobra.Command{
	Use:   "list-backends",
	Short: "List configured backends",
	Run: func(cmd *cobra.Command, args []string) {
		doListBackends()
	},
}

var identCmd = &cobra.Command{
	Use:   "ident",
	Short: "Get server instance ID",
	Run: func(cmd *cobra.Command, args []string) {
		doIdent()
	},
}

var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "Authenticate with the server",
	Run: func(cmd *cobra.Command, args []string) {
		token, _ := cmd.Flags().GetString("token")
		if token == "" {
			fmt.Print("Enter token: ")
			fmt.Scanln(&token)
		}
		doAuth(token)
	},
}

var registerCmd = &cobra.Command{
	Use:   "register",
	Short: "Register an application",
	Run: func(cmd *cobra.Command, args []string) {
		appName, _ := cmd.Flags().GetString("name")
		doRegister(appName)
	},
}

var createCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a secret",
	Run: func(cmd *cobra.Command, args []string) {
		appID, _ := cmd.Flags().GetString("appid")
		secretName, _ := cmd.Flags().GetString("name")
		backend, _ := cmd.Flags().GetString("backend")
		mountPath, _ := cmd.Flags().GetString("mount")
		data, _ := cmd.Flags().GetString("data")
		doCreate(appID, secretName, backend, mountPath, data)
	},
}

var getCmd = &cobra.Command{
	Use:   "get",
	Short: "Get a secret",
	Run: func(cmd *cobra.Command, args []string) {
		appID, _ := cmd.Flags().GetString("appid")
		secretName, _ := cmd.Flags().GetString("name")
		doGet(appID, secretName)
	},
}

var taintCmd = &cobra.Command{
	Use:   "taint",
	Short: "Taint a secret",
	Run: func(cmd *cobra.Command, args []string) {
		appID, _ := cmd.Flags().GetString("appid")
		secretName, _ := cmd.Flags().GetString("name")
		doTaint(appID, secretName)
	},
}

var untaintCmd = &cobra.Command{
	Use:   "untaint",
	Short: "Untaint a secret",
	Run: func(cmd *cobra.Command, args []string) {
		appID, _ := cmd.Flags().GetString("appid")
		secretName, _ := cmd.Flags().GetString("name")
		doUntaint(appID, secretName)
	},
}

var destroyCmd = &cobra.Command{
	Use:   "destroy",
	Short: "Destroy a secret",
	Run: func(cmd *cobra.Command, args []string) {
		appID, _ := cmd.Flags().GetString("appid")
		secretName, _ := cmd.Flags().GetString("name")
		doDestroy(appID, secretName)
	},
}

var isTaintedCmd = &cobra.Command{
	Use:   "istainted",
	Short: "Check if a secret is tainted",
	Run: func(cmd *cobra.Command, args []string) {
		appID, _ := cmd.Flags().GetString("appid")
		secretName, _ := cmd.Flags().GetString("name")
		doIsTainted(appID, secretName)
	},
}

var listAppsCmd = &cobra.Command{
	Use:   "list-apps",
	Short: "List registered applications",
	Run: func(cmd *cobra.Command, args []string) {
		table, _ := cmd.Flags().GetBool("table")
		doListApps(table)
	},
}

var listSecretsCmd = &cobra.Command{
	Use:   "list-secrets",
	Short: "List secrets for an application",
	Run: func(cmd *cobra.Command, args []string) {
		appID, _ := cmd.Flags().GetString("appid")
		doListSecrets(appID)
	},
}

var appUserCmd = &cobra.Command{
	Use:   "app-user",
	Short: "Manage application users",
}

var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Log out the current user",
	Run: func(cmd *cobra.Command, args []string) {
		doLogout()
	},
}

var createAppUserCmd = &cobra.Command{
	Use:   "create",
	Short: "Create an application user",
	Run: func(cmd *cobra.Command, args []string) {
		appID, _ := cmd.Flags().GetString("appid")
		name, _ := cmd.Flags().GetString("name")
		doCreateAppUser(appID, name)
	},
}

var listAppUsersCmd = &cobra.Command{
	Use:   "list-users",
	Short: "List application users",
	Run: func(cmd *cobra.Command, args []string) {
		table, _ := cmd.Flags().GetBool("table")
		doListAppUsers(table)
	},
}

var suspendAppUserCmd = &cobra.Command{
	Use:   "suspend-user",
	Short: "Suspend an application user",
	Run: func(cmd *cobra.Command, args []string) {
		userID, _ := cmd.Flags().GetString("userid")
		doSuspendAppUser(userID)
	},
}

var unsuspendAppUserCmd = &cobra.Command{
	Use:   "unsuspend-user",
	Short: "Unsuspend an application user",
	Run: func(cmd *cobra.Command, args []string) {
		userID, _ := cmd.Flags().GetString("userid")
		doUnsuspendAppUser(userID)
	},
}

var deleteAppUserCmd = &cobra.Command{
	Use:   "delete-user",
	Short: "Delete an application user",
	Run: func(cmd *cobra.Command, args []string) {
		userID, _ := cmd.Flags().GetString("userid")
		doDeleteAppUser(userID)
	},
}

var getAppUserTokenCmd = &cobra.Command{
	Use:   "get-token",
	Short: "Get an application user's token",
	Run: func(cmd *cobra.Command, args []string) {
		userID, _ := cmd.Flags().GetString("userid")
		doGetAppUserToken(userID)
	},
}

func main() {
	authCmd.Flags().String("token", "", "Authentication token")
	registerCmd.Flags().String("name", "", "Application name")
	createCmd.Flags().String("appid", "", "Application ID")
	createCmd.Flags().String("name", "", "Secret name")
	createCmd.Flags().String("backend", "", "Backend to use")
	createCmd.Flags().String("mount", "", "Mount path for the secret")
	createCmd.Flags().String("data", "", "Secret data in JSON format")
	getCmd.Flags().String("appid", "", "Application ID")
	getCmd.Flags().String("name", "", "Secret name")
	taintCmd.Flags().String("appid", "", "Application ID")
	taintCmd.Flags().String("name", "", "Secret name")
	untaintCmd.Flags().String("appid", "", "Application ID")
	untaintCmd.Flags().String("name", "", "Secret name")
	destroyCmd.Flags().String("appid", "", "Application ID")
	destroyCmd.Flags().String("name", "", "Secret name")
	isTaintedCmd.Flags().String("appid", "", "Application ID")
	isTaintedCmd.Flags().String("name", "", "Secret name")
	listAppsCmd.Flags().Bool("table", false, "Format output as a table")
	listSecretsCmd.Flags().String("appid", "", "Application ID")
	deleteAppCmd.Flags().String("appid", "", "Application ID")

	appUserCmd.AddCommand(createAppUserCmd)
	appUserCmd.AddCommand(listAppUsersCmd)
	appUserCmd.AddCommand(suspendAppUserCmd)
	appUserCmd.AddCommand(unsuspendAppUserCmd)
	appUserCmd.AddCommand(deleteAppUserCmd)
	appUserCmd.AddCommand(getAppUserTokenCmd)

	createAppUserCmd.Flags().String("appid", "", "Application ID")
	createAppUserCmd.Flags().String("name", "", "User name")
	listAppUsersCmd.Flags().Bool("table", false, "Format output as a table")
	suspendAppUserCmd.Flags().String("userid", "", "User ID")
	unsuspendAppUserCmd.Flags().String("userid", "", "User ID")
	deleteAppUserCmd.Flags().String("userid", "", "User ID")
	getAppUserTokenCmd.Flags().String("userid", "", "User ID")

	whoamiCmd.Flags().Bool("table", false, "Format output as a table")
	downloadAuditLogsCmd.Flags().Bool("json", false, "Download in JSON format")
	downloadAuditLogsCmd.Flags().Bool("csv", false, "Download in CSV format")
	downloadAuditLogsCmd.Flags().String("out", "", "Output filename")

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func getTokenPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".dcdr", "token"), nil
}

func saveToken(token string) error {
	path, err := getTokenPath()
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}

	return os.WriteFile(path, []byte(token), 0600)
}

func loadToken() (string, error) {
	path, err := getTokenPath()
	if err != nil {
		return "", err
	}

	token, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	return string(token), nil
}

func getHTTPClient() *http.Client {
	envSkipVerify, _ := strconv.ParseBool(os.Getenv("DCDR_SKIP_VERIFY"))
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: skipVerify || envSkipVerify},
		},
	}
}

func getServerAddr() string {
	addr := os.Getenv("DCDR_ADDR")
	if addr == "" {
		fmt.Fprintf(os.Stderr, "Error: DCDR_ADDR environment variable not set\n")
		os.Exit(1)
	}
	return addr
}

func doAPIRequest(method, url string, body []byte) (*http.Response, error) {
	client := getHTTPClient()
	req, err := http.NewRequest(method, getServerAddr()+"/api"+url, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}

	token := getAuthToken()
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	return client.Do(req)
}

func doIdent() {
	resp, err := doAPIRequest("GET", "/dcdrIdent", nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Println(string(body))
}

func getAuthToken() string {
	token, _ := rootCmd.Flags().GetString("token")
	if token != "" {
		return token
	}

	token = os.Getenv("DCDR_TOKEN")
	if token != "" {
		return token
	}

	token, err := loadToken()
	if err == nil {
		return token
	}

	return ""
}

func doAuth(token string) {
	client := getHTTPClient()
	req, err := http.NewRequest("POST", getServerAddr()+"/api/dcdrAuth", nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		if err := saveToken(token); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to cache token: %v\n", err)
		}
		fmt.Println("Authentication successful.")
	} else {
		body, _ := ioutil.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "Authentication failed: %s\n", string(body))
		os.Exit(1)
	}
}

func doRegister(appName string) {
	jsonData, _ := json.Marshal(map[string]string{"app_name": appName})
	resp, err := doAPIRequest("POST", "/dcdrRegister", jsonData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Println(string(body))
}

func doCreate(appID, secretName, backend, mountPath, data string) {
	var jsonData map[string]interface{}
	json.Unmarshal([]byte(data), &jsonData)
	requestBody, _ := json.Marshal(map[string]interface{}{
		"app_id":      appID,
		"secret_name": secretName,
		"backend":     backend,
		"mount_path":  mountPath,
		"data":        jsonData,
	})
	resp, err := doAPIRequest("POST", "/dcdrCreateSecret", requestBody)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Println(string(body))
}

func doGet(appID, secretName string) {
	jsonData, _ := json.Marshal(map[string]string{"app_id": appID, "secret_name": secretName})
	resp, err := doAPIRequest("POST", "/dcdrGet", jsonData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Println(string(body))
}

func doTaint(appID, secretName string) {
	jsonData, _ := json.Marshal(map[string]string{"app_id": appID, "secret_name": secretName})
	resp, err := doAPIRequest("POST", "/dcdrTaint", jsonData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Println(string(body))
}

func doUntaint(appID, secretName string) {
	jsonData, _ := json.Marshal(map[string]string{"app_id": appID, "secret_name": secretName})
	resp, err := doAPIRequest("POST", "/dcdrUntaint", jsonData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Println(string(body))
}

func doDestroy(appID, secretName string) {
	jsonData, _ := json.Marshal(map[string]string{"app_id": appID, "secret_name": secretName})
	resp, err := doAPIRequest("POST", "/dcdrDestroy", jsonData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Println(string(body))
}

func doIsTainted(appID, secretName string) {
	jsonData, _ := json.Marshal(map[string]string{"app_id": appID, "secret_name": secretName})
	resp, err := doAPIRequest("POST", "/dcdrIsTainted", jsonData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Println(string(body))
}

func doListApps(table bool) {
	resp, err := doAPIRequest("GET", "/dcdrListApps", nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)

	if table {
		var apps []map[string]string
		json.Unmarshal(body, &apps)

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
		fmt.Fprintln(w, "APP NAME\tAPP ID")
		for _, app := range apps {
			fmt.Fprintf(w, "%s\t%s\n", app["app_name"], app["app_id"])
		}
		w.Flush()
	} else {
		fmt.Println(string(body))
	}
}

func doListBackends() {
	resp, err := doAPIRequest("GET", "/dcdrListBackends", nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)

	var backends []map[string]interface{}
	json.Unmarshal(body, &backends)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
	fmt.Fprintln(w, "BACKEND\tAPPLICATIONS\tSECRETS")
	for _, backend := range backends {
		fmt.Fprintf(w, "%s\t%v\t%v\n", backend["backend"], backend["num_applications"], backend["num_secrets"])
	}
	w.Flush()
}

func doListSecrets(appID string) {
	jsonData, _ := json.Marshal(map[string]string{"app_id": appID})
	resp, err := doAPIRequest("POST", "/dcdrListSecrets", jsonData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)

	var secrets []map[string]interface{}
	json.Unmarshal(body, &secrets)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
	fmt.Fprintln(w, "SECRET NAME\tBACKEND\tMOUNT PATH\tTAINTED")
	for _, secret := range secrets {
		fmt.Fprintf(w, "%s\t%s\t%s\t%v\n", secret["secret_name"], secret["backend"], secret["mount_path"], secret["tainted"])
	}
	w.Flush()
}

func doDeleteApp(appID string) {
	jsonData, _ := json.Marshal(map[string]string{"app_id": appID})
	resp, err := doAPIRequest("POST", "/dcdrDeleteApp", jsonData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Println(string(body))
}

var whoamiCmd = &cobra.Command{
	Use:   "whoami",
	Short: "Print the current user's information",
	Run: func(cmd *cobra.Command, args []string) {
		table, _ := cmd.Flags().GetBool("table")
		doWhoami(table)
	},
}

var downloadAuditLogsCmd = &cobra.Command{
	Use:   "download-audit-logs",
	Short: "Download the audit log bundle",
	Run: func(cmd *cobra.Command, args []string) {
		jsonFormat, _ := cmd.Flags().GetBool("json")
		csvFormat, _ := cmd.Flags().GetBool("csv")
		outFile, _ := cmd.Flags().GetString("out")

		if !jsonFormat && !csvFormat {
			fmt.Fprintln(os.Stderr, "Error: either --json or --csv flag must be provided")
			os.Exit(1)
		}
		if jsonFormat && csvFormat {
			fmt.Fprintln(os.Stderr, "Error: only one of --json or --csv can be provided")
			os.Exit(1)
		}

		format := "csv"
		if jsonFormat {
			format = "json"
		}

		doDownloadAuditLogs(format, outFile)
	},
}

func doDownloadAuditLogs(format, outFile string) {
	url := fmt.Sprintf("/dcdrAudit/download?format=%s", format)
	resp, err := doAPIRequest("GET", url, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "Error downloading audit logs: %s\n", string(body))
		os.Exit(1)
	}

	if outFile == "" {
		// if no out file, pull it from the Content-Disposition header
		disposition := resp.Header.Get("Content-Disposition")
		if disposition != "" {
			if _, params, err := mime.ParseMediaType(disposition); err == nil {
				outFile = params["filename"]
			}
		}
		// if still no filename, generate a default one
		if outFile == "" {
			timestamp := time.Now().Format("2006-01-02-15-04-05")
			outFile = fmt.Sprintf("dcdr-audit-logs-%s.zip", timestamp)
		}
	}

	f, err := os.Create(outFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating file: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	_, err = io.Copy(f, resp.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error writing to file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Audit logs downloaded successfully to %s\n", outFile)
}

func doWhoami(table bool) {

	resp, err := doAPIRequest("GET", "/dcdrWhoami", nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)

	if table {
		var data map[string]string
		json.Unmarshal(body, &data)

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
		if _, ok := data["app_id"]; ok {
			fmt.Fprintln(w, "USER ID\tUSER NAME\tAPP ID\tAPP NAME")
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", data["user_id"], data["user_name"], data["app_id"], data["app_name"])
		} else {
			fmt.Fprintln(w, "USER ID\tUSER NAME")
			fmt.Fprintf(w, "%s\t%s\n", data["user_id"], data["user_name"])
		}
		w.Flush()
	} else {
		fmt.Println(string(body))
	}
}

func doLogout() {
	path, err := getTokenPath()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	if err := os.Remove(path); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Logged out successfully.")
}

func doCreateAppUser(appID, name string) {
	jsonData, _ := json.Marshal(map[string]string{"app_id": appID, "app_name": name})
	resp, err := doAPIRequest("POST", "/dcdrAppUser/create", jsonData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Println(string(body))
}

func doListAppUsers(table bool) {
	resp, err := doAPIRequest("GET", "/dcdrAppUser/list", nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)

	if table {
		var users []map[string]string
		json.Unmarshal(body, &users)

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
		fmt.Fprintln(w, "USER ID\tUSER NAME\tAPP ID\tAPP NAME\tSTATUS")
		for _, user := range users {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", user["user_id"], user["user_name"], user["app_id"], user["app_name"], user["status"])
		}
		w.Flush()
	} else {
		fmt.Println(string(body))
	}
}

func doSuspendAppUser(userID string) {
	jsonData, _ := json.Marshal(map[string]string{"user_id": userID})
	resp, err := doAPIRequest("POST", "/dcdrAppUser/suspend", jsonData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Println(string(body))
}

func doUnsuspendAppUser(userID string) {
	jsonData, _ := json.Marshal(map[string]string{"user_id": userID})
	resp, err := doAPIRequest("POST", "/dcdrAppUser/unsuspend", jsonData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Println(string(body))
}

func doDeleteAppUser(userID string) {
	jsonData, _ := json.Marshal(map[string]string{"user_id": userID})
	resp, err := doAPIRequest("POST", "/dcdrAppUser/delete", jsonData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Println(string(body))
}

func doGetAppUserToken(userID string) {
	jsonData, _ := json.Marshal(map[string]string{"user_id": userID})
	resp, err := doAPIRequest("POST", "/dcdrAppUser/getToken", jsonData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Println(string(body))
}