import sys
import subprocess
import shutil

def get_gpu_info():
    """Detects if the client has NVIDIA, AMD, or Apple Silicon."""
    info = {"type": "CPU", "available": False, "details": ""}
    
    # 1. Check for NVIDIA (NVSMI)
    if shutil.which("nvidia-smi"):
        info["type"] = "CUDA"
        info["available"] = True
        return info

    # 2. Check for Apple Silicon (Mac)
    if sys.platform == "darwin":
        # Simplified check for M1/M2/M3
        info["type"] = "MPS"
        info["available"] = True
        return info
        
    # 3. Fallback to CPU
    return info
