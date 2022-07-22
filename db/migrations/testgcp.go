// Package p contains an HTTP Cloud Function.
package p

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"html"
	"io"

	"google.golang.org/api/compute/v1"

	"net/http"
)

// HelloWorld prints the JSON encoded "message" field in the body
// of the request or "Hello, World!" if there isn't one.
func HelloWorld(w http.ResponseWriter, r *http.Request) {
	var d struct {
		Message string `json:"message"`
	}

	if err := json.NewDecoder(r.Body).Decode(&d); err != nil {
		switch err {
		case io.EOF:

			return
		default:
			log.Printf("json.NewDecoder: %v", err)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
	}
	err := insertNewVM()
	if err != nil {
		log.Printf("json.NewDecoder: %v", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	if d.Message == "" {
		fmt.Fprint(w, "Hello World!")
		return
	}
	fmt.Fprint(w, html.EscapeString(d.Message))
}
func insertNewVM() error {

	startSript := `#! /bin/bash apt-get update`
	myKey := "My key 1"
	ctx := context.Background()
	computeService, err := compute.NewService(ctx)
	if err != nil {
		log.Panic("error")
		return err
	}
	zone := "us-central1-a"
	projectID := "cr-lab-hraizada-2906225331"
	machineNamme := "mycomputeinstane"
	diskType := "projects/cr-lab-hraizada-2906225331/zones/us-central1-a/diskTypes/pd-balanced"
	diskName := machineNamme + "-disk"
	//network:="projects/" + projectID +"/global/networks/network123"
	subnetwork := "projects/cr-lab-hraizada-2906225331/regions/us-central1/subnetworks/default"
	machineType := "projects/cr-lab-hraizada-2906225331/zones/us-central1-a/machineTypes/n1-standard-1"
	myComputeInstane := &compute.Instance{
		Name:        machineNamme,
		Description: "An example instance for test",
		MachineType: machineType,
		Disks: []*compute.AttachedDisk{
			{
				AutoDelete: true,
				Boot:       true,
				Type:       "PERSISTENT",
				InitializeParams: &compute.AttachedDiskInitializeParams{
					DiskName:    diskName,
					DiskType:    diskType,
					SourceImage: "projects/debian-cloud/global/images/debian-11-bullseye-v20220719",
				},
			},
		},
		NetworkInterfaces: []*compute.NetworkInterface{
			{

				Subnetwork: subnetwork,
			},
		},
		Metadata: &compute.Metadata{
			Items: []*compute.MetadataItems{{
				Key:   "startup-script",
				Value: &startSript,
			},
				{
					Key:   "Key1",
					Value: &myKey,
				},
			},
		},
	}

	op, err := computeService.Instances.Insert(projectID, zone, myComputeInstane).Do()
	if err != nil {
		fmt.Println(err)
		return err
	}

	fmt.Println(op)
	return nil
}
