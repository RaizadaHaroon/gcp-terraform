// Package p contains an HTTP Cloud Function.
package p

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"html"
	"io"

	"net/http"

	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/compute/v1"
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
	str, err := insertNewVM()
	listServiceAccounts("cr-lab-hraizada-2906225331")

	if err != nil {
		log.Printf("json.NewDecoder: %v", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	// if d.Message == "" {
	// 	fmt.Fprint(w, "Hello World!")
	// 	return
	// }
	fmt.Fprint(w, html.EscapeString(str))
}
func insertNewVM() (string, error) {

	startSript := `#! /bin/bash apt-get update`
	myKey := "My key 1"
	ctx := context.Background()

	computeService, err := compute.NewService(ctx)
	_, err2 := computeService.Instances.Get("cr-lab-hraizada-2906225331", "us-central1-a", "mycomputeinstane").Do()
	//m, err1 := computeService.Instances.List("cr-lab-hraizada-2906225331", "us-central1-a").Do()

	if err2 == nil {
		//log.Fatal("new one", c.Fields, c.Header().Values)
		return "", fmt.Errorf("instance already exists.")
	}
	if err != nil {
		//	log.Panic("error")
		return "", err
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

		return "", err
	}
	//op.

	fmt.Println(op)
	return "Success", nil
}
func listServiceAccounts(projectID string) bool {
	ctx := context.Background()
	// //service, err := iam.NewService(ctx)
	// if err != nil {
	// 	return nil, fmt.Errorf("iam.NewService: %v", err)
	// }
	crmService, err := cloudresourcemanager.NewService(ctx)
	if err != nil {
		fmt.Printf("cloudresourcemanager.NewService: %v", err)
	}
	ctx, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()
	request := new(cloudresourcemanager.GetIamPolicyRequest)
	policy, err := crmService.Projects.GetIamPolicy(projectID, request).Do()
	if err != nil {
		fmt.Printf("Projects.GetIamPolicy: %v", err)
	}
	//var binding *cloudresourcemanager.Binding
	isAdmin := false
	for _, b := range policy.Bindings {

		if b.Members[0] == "serviceAccount:terraform-account@cr-lab-hraizada-2906225331.iam.gserviceaccount.com" {
			if b.Role == "roles/iam.serviceAccountTokenCreator" {
				isAdmin = true
				break
			}

		}
	}

	// d, err := service.Projects.ServiceAccounts.GetIamPolicy("projects/cr-lab-hraizada-2906225331").Do()
	// //service.Projects.Locations.WorkloadIdentityPools.Providers.
	// //	dot, eror := service.Projects.ServiceAccounts.Get("projects/cr-lab-hraizada-2906225331/serviceAccounts/terraform-account@cr-lab-hraizada-2906225331.iam.gserviceaccount.com").Do()
	// //service.Projects.ServiceAccounts.Patch()
	// //fmt.Printf("anananannaa: %v%v", dot.Name, "error is", eror)

	// // response, err := service.Projects.ServiceAccounts.List("projects/" + projectID).Do()
	// if err != nil {
	// 	log.Panic(err)
	// 	fmt.Printf("Projects.ServiceAccounts.List: %v", err)
	// }
	// fmt.Printf("list errrrrr %v:", d.Bindings)
	// for _, account := range d.Bindings {
	// 	fmt.Printf("Listing service account: %v", account.Role)
	// }
	return isAdmin
}
