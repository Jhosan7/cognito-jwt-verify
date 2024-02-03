package utils

type cacheItem struct {
	Kid string
	Jwk JwkWithKid
}

type Cache struct {
	items []cacheItem
}

func NewCache() *Cache {
	return &Cache{items: []cacheItem{}}
}

func (c *Cache) Remove(kid string) {
	for i, item := range c.items {
		if item.Kid == kid {
			c.items = append(c.items[:i], c.items[i+1:]...)
			break
		}
	}
}

func (c *Cache) Add(kid string, jwk JwkWithKid) {
	c.Remove(kid)
	c.items = append(c.items, cacheItem{Kid: kid, Jwk: jwk})
}

func (c *Cache) Get(kid string) (JwkWithKid, bool) {
	for _, item := range c.items {
		if item.Kid == kid {
			return item.Jwk, true
		}
	}

	return JwkWithKid{}, false
}

func (c *Cache) Clear() {
	c.items = []cacheItem{}
}
