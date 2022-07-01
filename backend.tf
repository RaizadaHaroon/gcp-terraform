terraform {
  backend "gcs" {
    bucket = "cr-lab-hraizada-2906225331-tfstate"
    credentials = "./creds/serviceaccount.json"
  }
}
