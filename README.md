# FDexplorer

File descriptors explorer

```go
import "github.com/theFido/fdexplorer/pkg/fdexplorer"

func main() {
    conns := fdexplorer.GetSummary()
	fmt.Println(conns)
}
```