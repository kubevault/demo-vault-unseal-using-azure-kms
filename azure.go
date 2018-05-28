package main

import (
	"context"
	"encoding/base64"
	"path/filepath"

	kv "github.com/Azure/azure-sdk-for-go/services/keyvault/2016-10-01/keyvault"
	kvmgmt "github.com/Azure/azure-sdk-for-go/services/keyvault/mgmt/2016-10-01/keyvault"
	"github.com/Azure/go-autorest/autorest/to"
	"github.com/golang/glog"
	"github.com/pkg/errors"
)

type KVService struct {
	KeyClient   kv.BaseClient
	VaultClient kvmgmt.VaultsClient
	Ctx         context.Context
}

func NewKVService(cfg *Config, configFilePath string) (*KVService, error) {
	k := &KVService{
		Ctx: context.Background(),
	}

	k.VaultClient = kvmgmt.NewVaultsClient(cfg.SubscriptionID)
	auth, err := cfg.GetManagementToken(AuthGrantType())
	if err != nil {
		return nil, errors.Wrap(err, "failed to get  OAuth token for managing resources")
	}

	k.VaultClient.Authorizer = auth
	k.VaultClient.AddToUserAgent(kvmgmt.UserAgent())

	auth, err = cfg.GetKeyVaultToken(AuthGrantType())
	if err != nil {
		return nil, errors.Wrap(err, "failed to get  OAuth token for key vault resources")
	}
	k.KeyClient = kv.New()
	k.KeyClient.Authorizer = auth
	k.KeyClient.AddToUserAgent(kv.UserAgent())

	return k, nil
}

func (k *KVService) GetVault(resourceGroup, vaultName string) (vaultUrl *string, err error) {

	vault, err := k.VaultClient.Get(k.Ctx, resourceGroup, vaultName)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get vault")
	}
	return vault.Properties.VaultURI, nil
}

// Encrypt encrypts with an existing key
func (k *KVService) Encrypt(data []byte, vaultBaseUrl string, keyName string, keyVersion string) (*string, error) {

	value := base64.RawURLEncoding.EncodeToString(data)
	parameter := kv.KeyOperationsParameters{
		Algorithm: kv.RSA15,
		Value:     &value,
	}

	result, err := k.KeyClient.Encrypt(k.Ctx, vaultBaseUrl, keyName, keyVersion, parameter)
	if err != nil {
		glog.Infoln("Failed to encrypt, error: ", err)
		return nil, errors.Wrap(err, "failed to encrypt data")
	}
	return result.Result, nil
}

// Decrypt decrypts with an existing key
func (k *KVService) Decrypt(data string, subscriptionID string, vaultBaseUrl string, keyName string, keyVersion string) ([]byte, error) {
	parameter := kv.KeyOperationsParameters{
		Algorithm: kv.RSA15,
		Value:     &data,
	}

	result, err := k.KeyClient.Decrypt(k.Ctx, vaultBaseUrl, keyName, keyVersion, parameter)
	if err != nil {
		glog.Infoln("failed to decrypt, error: ", err)
		return nil, errors.Wrap(err, "failed to decrypt data")
	}
	bytes, err := base64.RawURLEncoding.DecodeString(*result.Result)
	return bytes, nil
}

//SetSecret will store secret in azure key vault
func (k *KVService) SetSecret(vaultBaseUrl, secretName, value string, tags ...map[string]*string) error {
	parameter := kv.SecretSetParameters{
		Value:       to.StringPtr(value),
		// Tags:        tags,
		ContentType: to.StringPtr("password"),
	}

	_, err := k.KeyClient.SetSecret(k.Ctx, vaultBaseUrl, secretName, parameter)
	if err != nil {
		return errors.Wrap(err, "unable to set secrets in key vault")
	}

	return nil
}

//GetSecret will give secret in response
func (k *KVService) GetSecret(vaultBaseUrl, secretName string) (*string, error) {
	// finding latest version
	var version string
	resp, err := k.KeyClient.GetSecretVersions(k.Ctx, vaultBaseUrl, secretName, to.Int32Ptr(5))
	if err != nil {
		return nil, errors.Wrap(err, "unable to get secret versions")
	}

	// should contain one version of secret
	// for resp.NotDone() {
	if resp.NotDone() {
		items := resp.Values()
		version = filepath.Base(to.String(items[0].ID))

		//for _,item := range items {
		//	fmt.Println(*item.ID)
		//	fmt.Println(*item.Attributes.Created)
		//}
		//err = resp.Next()
		//if err!=nil {
		//	return nil, errors.Wrap(err, "unable to get next pages of version")
		//}
		//fmt.Println("iterating..")
	}

	sr, err := k.KeyClient.GetSecret(k.Ctx, vaultBaseUrl, secretName, version)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to get secret(%s) of version(%s)", secretName, version)
	}

	return sr.Value, nil
}
