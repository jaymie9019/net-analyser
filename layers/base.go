package layers

type Layer interface {
	LayerType() LayerType

	// LayerContents 该层的字节 slice
	LayerContents() []byte

	// LayerPayload 该层包含的字节内容，但是不包含该层本身的协议内容
	LayerPayload() []byte
}

// LinkLayer 链路层
type LinkLayer interface {
	Layer
}

// NetworkLayer 网络层
type NetworkLayer interface {
	Layer
}

// TransportLayer 传输层
type TransportLayer interface {
	Layer
}

// ApplicationLayer 应用层
type ApplicationLayer interface {
	Layer
	Payload() []byte
}

// 对 layer 的实现，这是一个实现的基础类

// BaseLayer 所有 layers 的基类
type BaseLayer struct {
	Contents []byte
	Payload  []byte
}

func (b *BaseLayer) LayerContents() []byte { return b.Contents }

func (b *BaseLayer) LayerPayload() []byte { return b.Payload }
