package main

type Product struct {
	Available bool
	Name      string
	Message   string
	Price     int64
}

var products [100]Product

func init() {

	for k, _ := range products {
		var p Product
		p.Available = false
		products[k] = p
	}

	var shirt Product
	shirt.Available = true
	shirt.Name = "Shirt"
	shirt.Message = "Congratulations! You bought a shirt."
	shirt.Price = 25

	var hoodie Product
	hoodie.Available = true
	hoodie.Name = "Hoodie"
	hoodie.Message = "Congratulations! You bought a hoodie."
	hoodie.Price = 35

	var stick Product
	stick.Available = true
	stick.Name = "Poking stick"
	stick.Message = "Congratulations! You bought a poking stick."
	stick.Price = 75

	var flag Product
	flag.Available = true
	flag.Name = "Flag"
	flag.Message = "TG20{I_just_want_to_buy_a_real_flag}"
	flag.Price = 1337

	products[10] = shirt
	products[11] = hoodie
	products[12] = stick
	products[13] = flag
}
