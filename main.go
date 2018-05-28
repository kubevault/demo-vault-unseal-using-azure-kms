package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/golang/glog"
	vaultapi "github.com/hashicorp/vault/api"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

var (
	//configFilePath   = "/home/ac/go/src/github.com/soter/demo-vault-unseal-using-azure-kms/dist/config.json"
	configFilePath   = "/etc/config/config.json"
	secretNamePrefix = "vault-test"
)

func NewRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:                "vault initializer and unsealer",
		DisableAutoGenTag:  true,
		DisableFlagParsing: true,
		Run: func(cmd *cobra.Command, args []string) {
			vaultClient, err := NewVaultClient("127.0.0.1", "8200")
			if err != nil {
				glog.Fatal("unable to create vault client: ", err)
			}

			config, err := GetConfig(configFilePath)
			if err != nil {
				glog.Fatal("unable to get config", err)
			}

			kvService, err := NewKVService(config, configFilePath)
			if err != nil {
				glog.Fatal(err)
			}
			vaultBaseUrl, err := kvService.GetVault(config.ResourceGroup, config.ProviderVaultName)
			if err != nil {
				glog.Fatal(err)
			}

			for {
				initialized, err := vaultClient.Sys().InitStatus()
				if err != nil {
					glog.Errorf("failed to get initialized status. reason : %v\n", err)
				} else {
					if !initialized {
						err := Init(vaultClient,kvService,*vaultBaseUrl)
						if err!=nil {
							glog.Fatal("failed to initialize:", err)
						}
					} else {
						fmt.Println("vault is initialized")
						break
					}

				}
				time.Sleep(10 * time.Second)
			}

			for {
				resp, err := vaultClient.Sys().SealStatus()
				if err != nil {
					glog.Errorln("failed to check seal status: ", err)
				} else {
					if resp.Sealed {
						err := Unseal(vaultClient, kvService, *vaultBaseUrl)
						if err != nil {
							glog.Errorln("failed to unseal vault: ", err)
						}
					} else {
						fmt.Println("vault is unsealed")
					}
				}

				time.Sleep(10 * time.Second)
			}

		},
	}

	cmd.PersistentFlags().AddGoFlagSet(flag.CommandLine)
	// ref: https://github.com/kubernetes/kubernetes/issues/17162#issuecomment-225596212
	flag.CommandLine.Parse([]string{})

	return cmd
}

func main() {

	if err := NewRootCmd().Execute(); err != nil {
		os.Exit(1)
	}

	os.Exit(0)

	//config, err := GetConfig(configFilePath)
	//if err!=nil {
	//	glog.Fatal("unable to get config", err)
	//}
	//
	//kvService, err := NewKVService(config.SubscriptionID, configFilePath)
	//if err!=nil {
	//	glog.Fatal(err)
	//}
	//vaultBaseUrl, err := kvService.GetVault(config.ResourceGroup,config.ProviderVaultName)
	//if err!=nil {
	//	glog.Fatal(err)
	//}
	//fmt.Println(*vaultBaseUrl)
	//
	//fmt.Println("setting a secret..")
	//
	//err = kvService.SetSecret(*vaultBaseUrl, secretName, "test")
	//if err!=nil {
	//	glog.Fatal(err)
	//}
	//
	//fmt.Println("getting a secret..")
	//
	//value, err := kvService.GetSecret(*vaultBaseUrl, secretName)
	//if err!=nil {
	//	glog.Fatal(err)
	//}
	//
	//fmt.Println(*value)
}

func Init(cl *vaultapi.Client, kv *KVService, vaultBaseUrl string) error {
	resp, err := cl.Sys().Init(&vaultapi.InitRequest{
		SecretShares:    5,
		SecretThreshold: 3,
	})
	if err != nil {
		return errors.Wrap(err, "error initialising vault")
	}

	for i, key := range resp.Keys {
		keyID := getKeyName(i)
		err = kv.SetSecret(vaultBaseUrl, keyID, base64.StdEncoding.EncodeToString([]byte(key)))
		if err != nil {
			return errors.Wrap(err, "failed to store key")
		}
	}

	err = kv.SetSecret(vaultBaseUrl, getRootTokenName(), base64.StdEncoding.EncodeToString([]byte(resp.RootToken)))
	if err != nil {
		return errors.Wrap(err, "failed to store root token")
	}

	return nil
}

func Unseal(cl *vaultapi.Client, kv *KVService, vaultBaseUrl string) error {
	for i := 0; ; i++ {
		keyID := getKeyName(i)

		glog.Infoln("retrieving key from kms service...")
		k, err := kv.GetSecret(vaultBaseUrl, keyID)
		if err != nil {
			return errors.Wrapf(err, "unable to get key '%s'", keyID)
		}

		data, err := base64.StdEncoding.DecodeString(*k)
		if err != nil {
			return errors.Wrapf(err, "failed to decode key '%s'", keyID)
		}

		glog.Infoln("sending unseal request to vault...")
		resp, err := cl.Sys().Unseal(string(data))
		if err != nil {
			return errors.Wrap(err, "fail to send unseal request to vault")
		}

		glog.Infoln("got unseal response: %+v", *resp)

		if !resp.Sealed {
			return nil
		}

		// if progress is 0, we failed to unseal vault.
		if resp.Progress == 0 {
			return fmt.Errorf("failed to unseal vault. progress reset to 0")
		}
	}
}

func getKeyName(id int) string {
	return secretNamePrefix + "-" + strconv.Itoa(id)
}

func getRootTokenName() string {
	return secretNamePrefix + "-root-token"
}

func NewVaultClient(hostname string, port string) (*vaultapi.Client, error) {
	cfg := vaultapi.DefaultConfig()
	podURL := fmt.Sprintf("https://%s:%s", hostname, port)
	cfg.Address = podURL
	tlsConfig := &vaultapi.TLSConfig{
		Insecure: true,
	}
	cfg.ConfigureTLS(tlsConfig)
	return vaultapi.NewClient(cfg)
}
