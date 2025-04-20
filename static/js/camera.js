// Función para inicializar la cámara
async function initCamera(videoElement) {
    try {
        const stream = await navigator.mediaDevices.getUserMedia({ video: true });
        videoElement.srcObject = stream;
        return true;
    } catch (error) {
        console.error('Error al acceder a la cámara:', error);
        return false;
    }
}

// Función para capturar foto
function capturePhoto(videoElement, canvasElement) {
    const context = canvasElement.getContext('2d');
    // Establecer dimensiones del canvas igual al video
    canvasElement.width = videoElement.videoWidth;
    canvasElement.height = videoElement.videoHeight;
    // Dibujar el frame actual del video en el canvas
    context.drawImage(videoElement, 0, 0, canvasElement.width, canvasElement.height);
    // Convertir la imagen a formato base64
    return canvasElement.toDataURL('image/jpeg');
}

// Función para detener la cámara
function stopCamera(videoElement) {
    if (videoElement.srcObject) {
        videoElement.srcObject.getTracks().forEach(track => track.stop());
        videoElement.srcObject = null;
    }
}