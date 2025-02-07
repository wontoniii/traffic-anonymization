package network

import "os"

type Filter struct {
	FileName string
	Flt      string
}

func LoadFilter(filename string) (*Filter, error) {
	f := &Filter{}
	f.FileName = filename
	if err := f.Reload(); err != nil {
		return nil, err
	}
	return f, nil
}

func (f *Filter) Reload() error {
	buf, err := os.ReadFile(f.FileName)
	if err != nil {
		return err
	}
	f.Flt = string(buf)
	return nil
}
