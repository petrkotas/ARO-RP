package env

// Copyright (c) Microsoft Corporation.
// Licensed under the Apache License 2.0.

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/Azure/ARO-RP/pkg/util/keyvault"
)

type CertificateRefresher interface {
	Start(context.Context) error
	GetCertificates() (*rsa.PrivateKey, []*x509.Certificate)
}

type refreshingCertificate struct {
	lock     sync.RWMutex
	certs    []*x509.Certificate
	key      *rsa.PrivateKey
	interval time.Duration
	logger   *logrus.Entry
	kv       keyvault.Manager
	certName string
	stop     <-chan struct{}
}

func newCertificateRefresher(logger *logrus.Entry, interval time.Duration, kv keyvault.Manager, certificateName string, stop <-chan struct{}) CertificateRefresher {
	return &refreshingCertificate{
		logger:   logger,
		interval: interval,
		kv:       kv,
		certName: certificateName,
		stop:     stop,
	}
}

func (r *refreshingCertificate) Start(ctx context.Context) error {
	// initial pull to get the certificate start
	err := r.fetchCertificateOnce(ctx)
	if err != nil {
		return err
	}

	r.fetchCertificate(ctx)

	return nil
}

// GetCertificates loads the certificate from the synced store safe to use concurently
func (r *refreshingCertificate) GetCertificates() (*rsa.PrivateKey, []*x509.Certificate) {
	r.lock.RLock()
	defer r.lock.RUnlock()

	return r.key, r.certs
}

// fetchCertificateOnce access keyvault via preset getter and download new set
// of certificates.
// in case of failure error is returned and old certificate is left in the
// synced store
func (r *refreshingCertificate) fetchCertificateOnce(ctx context.Context) error {
	key, certs, err := r.kv.GetCertificateSecret(ctx, r.certName)
	if err != nil {
		return err
	}

	r.lock.Lock()
	defer r.lock.Unlock()
	r.key = key
	r.certs = certs

	return nil
}

// fetchCertificate starts goroutine to poll certificates
func (r *refreshingCertificate) fetchCertificate(ctx context.Context) {
	ticker := time.NewTicker(r.interval)

	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-r.stop:
				return
			case <-ticker.C:
				err := r.fetchCertificateOnce(ctx)
				if err != nil {
					r.logger.Errorf("cannot pull certificate leaving old one, %s", err.Error())
				}
			}
		}
	}()
}
