import torch
import torch.nn as nn
import onnx

class Autoencoder(nn.Module):
    def __init__(self, input_dim=77, encoding_dim=8):
        super(Autoencoder, self).__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 32),
            nn.ReLU(),
            nn.Linear(32, encoding_dim)
        )
        self.decoder = nn.Sequential(
            nn.Linear(encoding_dim, 32),
            nn.ReLU(),
            nn.Linear(32, input_dim)
        )

    def forward(self, x):
        latent = self.encoder(x)
        reconstruction = self.decoder(latent)
        return reconstruction, latent

def export():
    model = Autoencoder()
    state_dict = torch.load('models/autoencoder.pth', map_location='cpu')
    model.load_state_dict(state_dict)
    model.eval()

    dummy_input = torch.randn(1, 77)
    torch.onnx.export(
        model, 
        dummy_input, 
        "models/autoencoder.onnx", 
        export_params=True,
        opset_version=12,
        do_constant_folding=True,
        input_names=['input'],
        output_names=['output', 'latent'],
        dynamic_axes={'input': {0: 'batch_size'}, 'output': {0: 'batch_size'}, 'latent': {0: 'batch_size'}}
    )
    print("Exported models/autoencoder.onnx with named outputs: ['output', 'latent']")

if __name__ == "__main__":
    export()
