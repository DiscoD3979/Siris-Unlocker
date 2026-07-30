// ============================================
// 1. CANVAS BACKGROUND — exact copy from index1.html
// ============================================

const bgCanvas = document.getElementById('bg-canvas');
const context = bgCanvas.getContext('2d');
const canvasBuffer = document.createElement('canvas');
const contextBuffer = canvasBuffer.getContext('2d');

let W, H;

function resizeBgCanvas() {
    W = window.innerWidth;
    H = window.innerHeight;
    bgCanvas.width = W;
    bgCanvas.height = H;
    canvasBuffer.width = W;
    canvasBuffer.height = H;
}
resizeBgCanvas();
window.addEventListener('resize', resizeBgCanvas);

// Color state
var c_colorTime = 500;
var colorTime = c_colorTime;
var colorType = 1;
var colorRed = 255, colorGreen = 20, colorBlue = 20;
var colorRGBA = "rgba(red,green,blue,opacity)";

// Angle state
var aMove1 = 0, aMove2 = 0, aMove3 = 0, aMove4 = 0, aMove5 = 0;

// Ring data arrays
var largeRingOutside = new Array(60), largeRingInside = new Array(60);
var smallRing = new Array(16);
var middleRingMain = 3, middleRingSecondary = 0;

for(var i = 0; i < 60; i++) { largeRingOutside[i] = largeRingInside[i] = 0; }
for(var i = 0; i < 16; i++) { smallRing[i] = 0; }

// Size variables
var posX = 0, posY = 0, posR = 0, posX2 = 0, posY2 = 0;
var r1_1 = 5, r1_2 = 20, r1_3 = 40, r2 = 60;
var r3_1 = 200, r3_2 = 210, r3_3 = 220;
var r4 = 380, r5 = 400;
var h1 = 200, h2 = 200, rChange = 0;
var v = 0, styleTemp = 0, lineTemp = 0, hTemp = 0;
var audioFreqAvg = 0;

function colorChange() {
    if(colorTime != 0) { colorTime--; }
    else { colorTime = c_colorTime; colorType = colorType + 1 > 3 ? 1 : colorType + 1; }
    
    switch(true) {
        case (colorType == 1 && colorRed < 255): colorRed++; colorGreen--; colorBlue--; break;
        case (colorType == 2 && colorGreen < 255): colorGreen++; colorRed--; colorBlue--; break;
        case (colorType == 3 && colorBlue < 255): colorBlue++; colorRed--; colorGreen--; break;
    }
    if(colorRed == 255) { colorGreen = 20; colorBlue = 20; }
    if(colorGreen == 255) { colorRed = 20; colorBlue = 20; }
    if(colorBlue == 255) { colorRed = 20; colorGreen = 20; }
    colorRGBA = "rgba(red,green,blue,opacity)".replace("red",colorRed).replace("green",colorGreen).replace("blue",colorBlue);
}

function angleChange() {
    aMove1 = aMove1 + audioFreqAvg * 3 + 0.02;
    if(aMove1 >= 360) aMove1 -= 360;
    aMove2 = aMove2 + audioFreqAvg * 0 + 0.3;
    if(aMove2 >= 360) aMove2 -= 360;
    aMove3 = aMove3 + audioFreqAvg * 6 + 0.04;
    if(aMove3 >= 360) aMove3 -= 360;
    aMove4 = aMove4 + audioFreqAvg * 0.5 + 0.005;
    if(aMove4 >= 360) aMove4 -= 360;
    aMove5 = aMove5 + audioFreqAvg * 0.5 + 0.01;
    if(aMove5 >= 360) aMove5 -= 360;
}

function myRound(style, x, y, r) {
    contextBuffer.beginPath();
    contextBuffer.fillStyle = style;
    contextBuffer.arc(x, y, r, 0, 2 * Math.PI, false);
    contextBuffer.fill();
    contextBuffer.closePath();
}

function myLine(style, lineWidth, x1, y1, x2, y2) {
    contextBuffer.beginPath();
    contextBuffer.strokeStyle = style;
    contextBuffer.lineWidth = lineWidth;
    contextBuffer.moveTo(x1, y1);
    contextBuffer.lineTo(x2, y2);
    contextBuffer.stroke();
    contextBuffer.closePath();
}

function myArc(style, lineWidth, x, y, r, start, end, clock) {
    contextBuffer.beginPath();
    contextBuffer.strokeStyle = style;
    contextBuffer.lineWidth = lineWidth;
    contextBuffer.arc(x, y, r, start, end, clock);
    contextBuffer.stroke();
    contextBuffer.closePath();
}

function smallRingArcAnimation() {
    styleTemp = colorRGBA.replace("opacity", 0.6 + audioFreqAvg * 4).replace("red",colorRed).replace("green",colorGreen).replace("blue",colorBlue);
    lineTemp = 2;
    posR = r1_3;
    myArc(styleTemp, lineTemp, W/2, H/2, posR, 0 + aMove4, Math.PI * 2/3 + aMove4, false);
    myArc(styleTemp, lineTemp, W/2, H/2, posR, Math.PI * 1 + aMove4, Math.PI * 5/3 + aMove4, false);
    posR = r1_2;
    myArc(styleTemp, lineTemp, W/2, H/2, posR, 0 - aMove5, Math.PI * 1/3 - aMove5, false);
    myArc(styleTemp, lineTemp, W/2, H/2, posR, Math.PI * 2/3 - aMove5, Math.PI * 1 - aMove5, false);
    myArc(styleTemp, lineTemp, W/2, H/2, posR, Math.PI * 4/3 - aMove5, Math.PI * 5/3 - aMove5, false);
    posR = (r1_1 + audioFreqAvg * 30) > 10 ? 10 : (r1_1 + audioFreqAvg * 30);
    myArc(styleTemp, lineTemp, W/2, H/2, posR, 0, Math.PI * 2, false);
}

function smallRingRoundAnimation() {
    for(var j = 0; j < 16; j++) {
        v = audioFreqAvg * 8;
        if(v > 1) v = 1;
        styleTemp = colorRGBA.replace("opacity", 0.4 + (audioFreqAvg * 80) / 20).replace("red",colorRed).replace("green",colorGreen).replace("blue",colorBlue);
        posX = Math.cos((j * 22.5 - aMove2) / 180 * Math.PI) * (r2) + W/2;
        posY = Math.sin((j * 22.5 - aMove2) / 180 * Math.PI) * (r2) + H/2;
        posR = 3 + v * 1;
        myRound(styleTemp, posX, posY, posR);
        lineTemp = 2;
        styleTemp = colorRGBA.replace("opacity", 0.5).replace("red",colorRed).replace("green",colorGreen).replace("blue",colorBlue);
        posX = Math.cos((j * 22.5 - aMove2) / 180 * Math.PI) * (r2 - v * 20) + W/2;
        posY = Math.sin((j * 22.5 - aMove2) / 180 * Math.PI) * (r2 - v * 20) + H/2;
        posX2 = Math.cos((j * 22.5 - aMove2) / 180 * Math.PI) * (r2 + v * 120) + W/2;
        posY2 = Math.sin((j * 22.5 - aMove2) / 180 * Math.PI) * (r2 + v * 120) + H/2;
        myLine(styleTemp, lineTemp, posX, posY, posX2, posY2);
        if(smallRing[j] <= v * 120) { smallRing[j] = v * 120; }
        else { smallRing[j] = smallRing[j] - 1; }
        if(smallRing[j] <= 0) { smallRing[j] = 0; }
        styleTemp = colorRGBA.replace("opacity", 0.5).replace("red",colorRed).replace("green",colorGreen).replace("blue",colorBlue);
        posX = Math.cos((j * 22.5 - aMove2) / 180 * Math.PI) * (r2 + smallRing[j]) + W/2;
        posY = Math.sin((j * 22.5 - aMove2) / 180 * Math.PI) * (r2 + smallRing[j]) + H/2;
        posR = 3;
        myRound(styleTemp, posX, posY, posR);
    }
}

function middleRingAnimation() {
    styleTemp = colorRGBA.replace("opacity", 0.5 + audioFreqAvg * 4).replace("red",colorRed).replace("green",colorGreen).replace("blue",colorBlue);
    posX = Math.cos((aMove3 + 90) / 180 * Math.PI) * (r3_2) + W/2;
    posY = Math.sin((aMove3 + 90) / 180 * Math.PI) * (r3_2) + H/2;
    posR = 6 + audioFreqAvg * 10;
    myRound(styleTemp, posX, posY, posR);
    posX = Math.cos((aMove3 + 210) / 180 * Math.PI) * (r3_2) + W/2;
    posY = Math.sin((aMove3 + 210) / 180 * Math.PI) * (r3_2) + H/2;
    myRound(styleTemp, posX, posY, posR);
    posX = Math.cos((aMove3 + 330) / 180 * Math.PI) * (r3_2) + W/2;
    posY = Math.sin((aMove3 + 330) / 180 * Math.PI) * (r3_2) + H/2;
    myRound(styleTemp, posX, posY, posR);
    
    if(middleRingMain < audioFreqAvg * 50) { middleRingMain += 0.5; }
    else if(middleRingMain > audioFreqAvg * 50) { middleRingMain -= 0.5; }
    if(middleRingMain <= 3 || audioFreqAvg * 50 < 1) middleRingMain = 3;
    if(middleRingMain > 20) middleRingMain = 20;
    
    for(var i = 0; i < middleRingMain; i++) {
        styleTemp = colorRGBA.replace("opacity", 0.5 + audioFreqAvg * 4 - i * 0.08).replace("red",colorRed).replace("green",colorGreen).replace("blue",colorBlue);
        posX = Math.cos((aMove3 + 90 + (i+1) * 5) / 180 * Math.PI) * (r3_1) + W/2;
        posY = Math.sin((aMove3 + 90 + (i+1) * 5) / 180 * Math.PI) * (r3_1) + H/2;
        posR = 4 - 0.1 * (i+1);
        myRound(styleTemp, posX, posY, posR);
        posX = Math.cos((aMove3 + 210 + (i+1) * 5) / 180 * Math.PI) * (r3_1) + W/2;
        posY = Math.sin((aMove3 + 210 + (i+1) * 5) / 180 * Math.PI) * (r3_1) + H/2;
        myRound(styleTemp, posX, posY, posR);
        posX = Math.cos((aMove3 + 330 + (i+1) * 5) / 180 * Math.PI) * (r3_1) + W/2;
        posY = Math.sin((aMove3 + 330 + (i+1) * 5) / 180 * Math.PI) * (r3_1) + H/2;
        myRound(styleTemp, posX, posY, posR);
        posX = Math.cos((aMove3 + 90 - (i+1) * 5) / 180 * Math.PI) * (r3_1) + W/2;
        posY = Math.sin((aMove3 + 90 - (i+1) * 5) / 180 * Math.PI) * (r3_1) + H/2;
        myRound(styleTemp, posX, posY, posR);
        posX = Math.cos((aMove3 + 210 - (i+1) * 5) / 180 * Math.PI) * (r3_1) + W/2;
        posY = Math.sin((aMove3 + 210 - (i+1) * 5) / 180 * Math.PI) * (r3_1) + H/2;
        myRound(styleTemp, posX, posY, posR);
        posX = Math.cos((aMove3 + 330 - (i+1) * 5) / 180 * Math.PI) * (r3_1) + W/2;
        posY = Math.sin((aMove3 + 330 - (i+1) * 5) / 180 * Math.PI) * (r3_1) + H/2;
        myRound(styleTemp, posX, posY, posR);
    }
    
    if(middleRingSecondary < audioFreqAvg * 30) middleRingSecondary += 0.5;
    else if(middleRingSecondary > audioFreqAvg * 30) middleRingSecondary -= 0.5;
    if(middleRingSecondary <= 0 || audioFreqAvg * 30 < 1) middleRingSecondary = 0;
    if(middleRingSecondary > 18) middleRingSecondary = 18;
    
    for(var i = 0; i < middleRingSecondary; i++) {
        styleTemp = colorRGBA.replace("opacity", 0.5 + audioFreqAvg * 4 - i * 0.1).replace("red",colorRed).replace("green",colorGreen).replace("blue",colorBlue);
        posX = Math.cos((aMove3 + 90 + (i+1) * 5) / 180 * Math.PI) * (r3_3) + W/2;
        posY = Math.sin((aMove3 + 90 + (i+1) * 5) / 180 * Math.PI) * (r3_3) + H/2;
        posR = 4 - 0.1 * (i+1);
        myRound(styleTemp, posX, posY, posR);
        posX = Math.cos((aMove3 + 210 + (i+1) * 5) / 180 * Math.PI) * (r3_3) + W/2;
        posY = Math.sin((aMove3 + 210 + (i+1) * 5) / 180 * Math.PI) * (r3_3) + H/2;
        myRound(styleTemp, posX, posY, posR);
        posX = Math.cos((aMove3 + 330 + (i+1) * 5) / 180 * Math.PI) * (r3_3) + W/2;
        posY = Math.sin((aMove3 + 330 + (i+1) * 5) / 180 * Math.PI) * (r3_3) + H/2;
        myRound(styleTemp, posX, posY, posR);
        posX = Math.cos((aMove3 + 90 - (i+1) * 5) / 180 * Math.PI) * (r3_3) + W/2;
        posY = Math.sin((aMove3 + 90 - (i+1) * 5) / 180 * Math.PI) * (r3_3) + H/2;
        myRound(styleTemp, posX, posY, posR);
        posX = Math.cos((aMove3 + 210 - (i+1) * 5) / 180 * Math.PI) * (r3_3) + W/2;
        posY = Math.sin((aMove3 + 210 - (i+1) * 5) / 180 * Math.PI) * (r3_3) + H/2;
        myRound(styleTemp, posX, posY, posR);
        posX = Math.cos((aMove3 + 330 - (i+1) * 5) / 180 * Math.PI) * (r3_3) + W/2;
        posY = Math.sin((aMove3 + 330 - (i+1) * 5) / 180 * Math.PI) * (r3_3) + H/2;
        myRound(styleTemp, posX, posY, posR);
    }
}

function largeRingAnimation() {
    for(var i = 0; i < 30; i++) {
        v = audioFreqAvg * 5;
        styleTemp = colorRGBA.replace("opacity", 1).replace("red",colorRed).replace("green",colorGreen).replace("blue",colorBlue);
        posX = Math.cos((i * 3 - aMove1) / 180 * Math.PI) * (r4 - audioFreqAvg * rChange) + W/2;
        posY = Math.sin((i * 3 - aMove1) / 180 * Math.PI) * (r4 - audioFreqAvg * rChange) + H/2;
        posR = 3;
        myRound(styleTemp, posX, posY, posR);
        lineTemp = 1.5;
        posX = Math.cos((i * 3 - aMove1) / 180 * Math.PI) * (r4 - audioFreqAvg * rChange) + W/2;
        posY = Math.sin((i * 3 - aMove1) / 180 * Math.PI) * (r4 - audioFreqAvg * rChange) + H/2;
        posX2 = Math.cos((i * 3 - aMove1) / 180 * Math.PI) * ((r4 - audioFreqAvg * rChange) - v * h1 > r3_3 ? (r4 - audioFreqAvg * rChange) - v * h1 : r3_3) + W/2;
        posY2 = Math.sin((i * 3 - aMove1) / 180 * Math.PI) * ((r4 - audioFreqAvg * rChange) - v * h1 > r3_3 ? (r4 - audioFreqAvg * rChange) - v * h1 : r3_3) + H/2;
        myLine(styleTemp, lineTemp, posX, posY, posX2, posY2);
        if(largeRingInside[i] < v * h1) largeRingInside[i] = v * h1;
        else largeRingInside[i] = largeRingInside[i] - 1;
        if(largeRingInside[i] >= r4 - r3_3) largeRingInside[i] = r4 - r3_3;
        styleTemp = colorRGBA.replace("opacity", 0.5).replace("red",colorRed).replace("green",colorGreen).replace("blue",colorBlue);
        posX = Math.cos((i * 3 - aMove1) / 180 * Math.PI) * ((r4 - audioFreqAvg * rChange) - largeRingInside[i] > r3_3 ? (r4 - audioFreqAvg * rChange) - largeRingInside[i] : r3_3) + W/2;
        posY = Math.sin((i * 3 - aMove1) / 180 * Math.PI) * ((r4 - audioFreqAvg * rChange) - largeRingInside[i] > r3_3 ? (r4 - audioFreqAvg * rChange) - largeRingInside[i] : r3_3) + H/2;
        posR = 3;
        myRound(styleTemp, posX, posY, posR);
        
        v = audioFreqAvg * 5;
        styleTemp = colorRGBA.replace("opacity", 1).replace("red",colorRed).replace("green",colorGreen).replace("blue",colorBlue);
        posX = Math.cos((i * 3 + 180 - aMove1) / 180 * Math.PI) * (r4 - audioFreqAvg * rChange) + W/2;
        posY = Math.sin((i * 3 + 180 - aMove1) / 180 * Math.PI) * (r4 - audioFreqAvg * rChange) + H/2;
        posR = 3;
        myRound(styleTemp, posX, posY, posR);
        posX = Math.cos((i * 3 + 180 - aMove1) / 180 * Math.PI) * (r4 - audioFreqAvg * rChange) + W/2;
        posY = Math.sin((i * 3 + 180 - aMove1) / 180 * Math.PI) * (r4 - audioFreqAvg * rChange) + H/2;
        posX2 = Math.cos((i * 3 + 180 - aMove1) / 180 * Math.PI) * ((r4 - audioFreqAvg * rChange) - v * h1 > r3_3 ? (r4 - audioFreqAvg * rChange) - v * h1 : r3_3) + W/2;
        posY2 = Math.sin((i * 3 + 180 - aMove1) / 180 * Math.PI) * ((r4 - audioFreqAvg * rChange) - v * h1 > r3_3 ? (r4 - audioFreqAvg * rChange) - v * h1 : r3_3) + H/2;
        myLine(styleTemp, lineTemp, posX, posY, posX2, posY2);
        if(largeRingInside[i+30] < v * h1) largeRingInside[i+30] = v * h1;
        else largeRingInside[i+30] = largeRingInside[i+30] - 1;
        if(largeRingInside[i+30] >= r4 - r3_3) largeRingInside[i+30] = r4 - r3_3;
        styleTemp = colorRGBA.replace("opacity", 0.5).replace("red",colorRed).replace("green",colorGreen).replace("blue",colorBlue);
        posX = Math.cos((i * 3 + 180 - aMove1) / 180 * Math.PI) * ((r4 - audioFreqAvg * rChange) - largeRingInside[i+30] > r3_3 ? (r4 - audioFreqAvg * rChange) - largeRingInside[i+30] : r3_3) + W/2;
        posY = Math.sin((i * 3 + 180 - aMove1) / 180 * Math.PI) * ((r4 - audioFreqAvg * rChange) - largeRingInside[i+30] > r3_3 ? (r4 - audioFreqAvg * rChange) - largeRingInside[i+30] : r3_3) + H/2;
        posR = 3;
        myRound(styleTemp, posX, posY, posR);
    }
    for(var i = 30; i < 60; i++) {
        v = audioFreqAvg * 5;
        hTemp = r5 + v * h2;
        if(hTemp < r5 + 3) hTemp = r5;
        if(largeRingOutside[i-30] < (hTemp - r5) / 10) largeRingOutside[i-30] += 0.5;
        else if(largeRingOutside[i-30] > (hTemp - r5) / 10) largeRingOutside[i-30] -= 0.5;
        if(largeRingOutside[i-30] == 0) largeRingOutside[i-30] = 1;
        for(var j = 0; j < largeRingOutside[i-30]; j++) {
            styleTemp = colorRGBA.replace("opacity", 1 - (j * 10) / (r5 - 240)).replace("red",colorRed).replace("green",colorGreen).replace("blue",colorBlue);
            posX = Math.cos((i * 3 - 180 + aMove1) / 180 * Math.PI) * (r5 + j * 10 + audioFreqAvg * rChange) + W/2;
            posY = Math.sin((i * 3 - 180 + aMove1) / 180 * Math.PI) * (r5 + j * 10 + audioFreqAvg * rChange) + H/2;
            posR = 3;
            myRound(styleTemp, posX, posY, posR);
        }
        v = audioFreqAvg * 5;
        hTemp = r5 + v * h2;
        if(hTemp < r5 + 3) hTemp = r5;
        if(largeRingOutside[i] < (hTemp - r5) / 10) largeRingOutside[i] += 0.5;
        else if(largeRingOutside[i] > (hTemp - r5) / 10) largeRingOutside[i] -= 0.5;
        if(largeRingOutside[i] == 0) largeRingOutside[i] = 1;
        for(var j = 0; j < largeRingOutside[i]; j++) {
            styleTemp = colorRGBA.replace("opacity", 1 - (j * 10) / (r5 - 240)).replace("red",colorRed).replace("green",colorGreen).replace("blue",colorBlue);
            posX = Math.cos((i * 3 + aMove1) / 180 * Math.PI) * (r5 + j * 10 + audioFreqAvg * rChange) + W/2;
            posY = Math.sin((i * 3 + aMove1) / 180 * Math.PI) * (r5 + j * 10 + audioFreqAvg * rChange) + H/2;
            posR = 3;
            myRound(styleTemp, posX, posY, posR);
        }
    }
}

function animateBg() {
    audioFreqAvg = 0.02; // subtle constant movement
    contextBuffer.clearRect(0, 0, W, H);
    colorChange();
    largeRingAnimation();
    middleRingAnimation();
    smallRingRoundAnimation();
    smallRingArcAnimation();
    angleChange();
    context.clearRect(0, 0, W, H);
    context.drawImage(canvasBuffer, 0, 0);
    requestAnimationFrame(animateBg);
}
animateBg();

// ============================================
// 2. NAVIGATION
// ============================================

const pageContainer = document.getElementById('page-container');
const pageOrder = ['home', 'about', 'features', 'screens', 'changelog', 'download', 'admin', 'creator'];
let currentIndex = 0;
let isTransitioning = false;
const SESSION_DURATION = 5 * 60 * 1000; // 5 минут
let adminSession = false;
let sessionTimer = null;

function setAdminSession() {
    const exp = Date.now() + SESSION_DURATION;
    sessionStorage.setItem('siris_admin_exp', exp);
    adminSession = true;
}

function clearAdminSession() {
    sessionStorage.removeItem('siris_admin_exp');
    adminSession = false;
}

function checkAdminSession() {
    const exp = sessionStorage.getItem('siris_admin_exp');
    if (!exp) { adminSession = false; return false; }
    if (Date.now() > Number(exp)) {
        sessionStorage.removeItem('siris_admin_exp');
        adminSession = false;
        return false;
    }
    adminSession = true;
    return true;
}

function switchPage(newPageId) {
    const newIndex = pageOrder.indexOf(newPageId);
    if (newIndex === -1 || newIndex === currentIndex || isTransitioning) return;

    if (newPageId === 'admin') {
        checkAdminSession();
    }

    isTransitioning = true;
    window.scrollTo({ top: 0, behavior: 'smooth' });
    updateActiveLink(newPageId);

    const direction = newIndex > currentIndex ? 'right' : 'left';
    pageContainer.classList.add('page-out', `page-out-${direction}`);

    setTimeout(() => {
        pageContainer.innerHTML = pages[newPageId];
        currentIndex = newIndex;
        pageContainer.classList.remove('page-out', 'page-out-left', 'page-out-right');
        pageContainer.classList.add('page-in', `page-in-${direction}`);

        setTimeout(() => {
            pageContainer.classList.remove('page-in', 'page-in-left', 'page-in-right');
            attachDynamicHandlers();

            if (newPageId === 'changelog') loadGitHubReleases();
            if (newPageId === 'creator') startTypingAnimation();
            if (newPageId === 'admin') setupAdminPanel();
            if (newPageId === 'download' || newPageId === 'home') setupDownloadBtn();

            isTransitioning = false;
        }, 500);
    }, 400);
}

function updateActiveLink(pageId) {
    document.querySelectorAll('.nav__link').forEach(link => {
        link.classList.toggle('nav__link--active', link.getAttribute('data-page') === pageId);
    });
}

// Navigation clicks
document.querySelectorAll('.nav__link').forEach(link => {
    link.addEventListener('click', e => {
        e.preventDefault();
        const page = link.getAttribute('data-page');
        switchPage(page);
    });
});

// Logo click
document.querySelector('.logo')?.addEventListener('click', e => {
    e.preventDefault();
    switchPage('home');
});

// Admin trigger via footer link
document.getElementById('adminTrigger')?.addEventListener('click', e => {
    e.preventDefault();
    switchPage('admin');
});

// ============================================
// 3. MOBILE NAV TOGGLE
// ============================================

const navToggle = document.querySelector('.nav__toggle');
const navList = document.querySelector('.nav__list');

if (navToggle && navList) {
    navToggle.addEventListener('click', () => {
        const isOpen = navList.classList.toggle('nav__list--open');
        navToggle.setAttribute('aria-expanded', isOpen);
    });

    navList.querySelectorAll('.nav__link').forEach(link => {
        link.addEventListener('click', () => {
            navList.classList.remove('nav__list--open');
            navToggle.setAttribute('aria-expanded', 'false');
        });
    });

    document.addEventListener('click', e => {
        if (!e.target.closest('.nav') && navList.classList.contains('nav__list--open')) {
            navList.classList.remove('nav__list--open');
            navToggle.setAttribute('aria-expanded', 'false');
        }
    });
}

// ============================================
// 4. MODAL
// ============================================

const modal = document.getElementById('downloadModal');

function openModal() {
    modal.classList.add('show');
    modal.setAttribute('aria-hidden', 'false');
}

function closeModal() {
    modal.classList.remove('show');
    modal.setAttribute('aria-hidden', 'true');
}

document.querySelectorAll('.open-modal-btn').forEach(btn => {
    btn.addEventListener('click', openModal);
});

document.querySelector('.modal__close')?.addEventListener('click', closeModal);

modal?.addEventListener('click', e => {
    if (e.target === modal || e.target.classList.contains('modal__overlay')) closeModal();
});

document.addEventListener('keydown', e => {
    if (e.key === 'Escape') closeModal();
});

// ============================================
// 5. LIGHTBOX
// ============================================

const lightbox = document.getElementById('lightbox');
const lightboxImg = document.getElementById('lightbox-img');

function openLightbox(src) {
    lightboxImg.src = src;
    lightbox.classList.add('show');
    lightbox.setAttribute('aria-hidden', 'false');
}

function closeLightbox() {
    lightbox.classList.remove('show');
    lightbox.setAttribute('aria-hidden', 'true');
    lightboxImg.src = '';
}

function attachLightbox() {
    document.querySelectorAll('.screenshot-card').forEach(card => {
        card.addEventListener('click', () => {
            const img = card.querySelector('img');
            if (img) openLightbox(img.src);
        });
    });
}

document.querySelector('.lightbox__close')?.addEventListener('click', closeLightbox);
lightbox?.addEventListener('click', e => {
    if (e.target === lightbox) closeLightbox();
});

// ============================================
// 6. GITHUB API — REAL RELEASES
// ============================================

async function loadGitHubReleases() {
    const container = document.getElementById('changelog-container');
    if (!container) return;

    try {
        const response = await fetch('https://api.github.com/repos/DiscoD3979/Siris-Unlocker/releases?per_page=10');
        if (!response.ok) throw new Error('GitHub API error');

        const releases = await response.json();
        if (!releases.length) throw new Error('No releases');

        container.innerHTML = releases.map((release, i) => {
            const isLatest = i === 0;
            const date = new Date(release.published_at || release.created_at);
            const dateStr = date.toLocaleDateString('ru-RU', { year: 'numeric', month: 'long', day: 'numeric' });

            // Parse body into list items
            const bodyLines = (release.body || '')
                .split('\n')
                .filter(line => line.trim().startsWith('*') || line.trim().startsWith('-'))
                .map(line => line.replace(/^[\s\*\-]+/, '').trim())
                .filter(line => line.length > 0);

            // If no list items, try to split by newlines
            const items = bodyLines.length > 0 ? bodyLines : 
                (release.body || '')
                    .split('\n')
                    .filter(line => line.trim().length > 0 && !line.includes('##'))
                    .map(line => line.replace(/^[\s\*\-]+/, '').trim())
                    .filter(line => line.length > 0);

            // Calculate total downloads from all assets
            let totalDownloads = 0;
            if (release.assets && release.assets.length > 0) {
                release.assets.forEach(asset => {
                    totalDownloads += asset.download_count || 0;
                });
            }

            const listHtml = items.slice(0, 10).map(item => `<li>${escapeHtml(item)}</li>`).join('');
            const dlBtn = release.html_url ? `<a href="${escapeHtml(release.html_url)}" target="_blank" rel="noopener" class="btn btn--github release-dl-btn">⬇ Скачать ${escapeHtml(release.tag_name)}</a>` : '';

            return `
                <div class="changelog-entry">
                    <div class="changelog-entry__header">
                        <span class="changelog-entry__version">${escapeHtml(release.tag_name)}</span>
                        ${isLatest ? '<span class="changelog-entry__badge">Latest</span>' : ''}
                        <span class="changelog-entry__date">${dateStr}</span>
                    </div>
                    ${listHtml ? `<ul class="changelog-entry__list">${listHtml}</ul>` : ''}
                    <div class="changelog-entry__footer">
                        ${dlBtn}
                        ${totalDownloads > 0 ? `<span class="release-downloads">⬇ ${totalDownloads.toLocaleString()} загрузок</span>` : ''}
                    </div>
                </div>
            `;
        }).join('');

    } catch (err) {
        console.error('GitHub API error:', err);
        container.innerHTML = `
            <div class="changelog-loading" style="color: var(--text-muted);">
                Не удалось загрузить релизы. 
                <a href="https://github.com/DiscoD3979/Siris-Unlocker/releases" target="_blank" rel="noopener" style="color: var(--accent);">Смотреть на GitHub</a>
            </div>
        `;
    }
}

// ============================================
// 7. DOWNLOAD BUTTON — DYNAMIC EXE (IndexedDB)
// ============================================

const DB_NAME = 'SirisUnlockerDB';
const DB_VERSION = 1;
const STORE_NAME = 'exeStore';

function openDB() {
    return new Promise((resolve, reject) => {
        const req = indexedDB.open(DB_NAME, DB_VERSION);
        req.onupgradeneeded = (e) => {
            const db = e.target.result;
            if (!db.objectStoreNames.contains(STORE_NAME)) {
                db.createObjectStore(STORE_NAME, { keyPath: 'id' });
            }
        };
        req.onsuccess = (e) => resolve(e.target.result);
        req.onerror = (e) => reject(e.target.error);
    });
}

function saveExeToDB(data) {
    return openDB().then(db => {
        return new Promise((resolve, reject) => {
            const tx = db.transaction(STORE_NAME, 'readwrite');
            const store = tx.objectStore(STORE_NAME);
            store.put({ id: 'siris_exe_data', ...data });
            tx.oncomplete = () => resolve();
            tx.onerror = (e) => reject(e.target.error);
        });
    });
}

function loadExeFromDB() {
    return openDB().then(db => {
        return new Promise((resolve, reject) => {
            const tx = db.transaction(STORE_NAME, 'readonly');
            const store = tx.objectStore(STORE_NAME);
            const req = store.get('siris_exe_data');
            req.onsuccess = () => resolve(req.result);
            req.onerror = (e) => reject(e.target.error);
        });
    });
}

function downloadBlob(data) {
    const byteString = atob(data.base64);
    const ab = new ArrayBuffer(byteString.length);
    const ia = new Uint8Array(ab);
    for (let i = 0; i < byteString.length; i++) {
        ia[i] = byteString.charCodeAt(i);
    }
    const blob = new Blob([ab], { type: 'application/x-msdownload' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'SirisUnlocker.exe';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

function uploadToGoFile(file, onProgress) {
    return fetch('https://api.gofile.io/servers')
        .then(r => r.json())
        .then(data => {
            if (data.status !== 'ok') throw new Error('Не удалось получить сервер');
            const server = data.data.servers[0].name;
            return new Promise((resolve, reject) => {
                const form = new FormData();
                form.append('file', file);
                const xhr = new XMLHttpRequest();
                xhr.open('POST', `https://${server}.gofile.io/uploadFile`);
                xhr.upload.onprogress = (e) => {
                    if (e.lengthComputable && onProgress) {
                        onProgress(e.loaded, e.total);
                    }
                };
                xhr.onload = () => {
                    try {
                        const resp = JSON.parse(xhr.responseText);
                        if (resp.status === 'ok') resolve(resp.data);
                        else reject(new Error(resp.status));
                    } catch (e) { reject(e); }
                };
                xhr.onerror = () => reject(new Error('Ошибка сети'));
                xhr.send(form);
            });
        });
}

let downloadBtnSetup = false;

function setupDownloadBtn() {
    if (downloadBtnSetup) return;
    downloadBtnSetup = true;
    document.addEventListener('click', function(e) {
        const btn = e.target.closest('#downloadSiteBtn');
        if (!btn) return;
        e.preventDefault();
        loadExeFromDB().then(data => {
            if (data) {
                if (data.netlifyUrl) {
                    window.location.href = data.netlifyUrl;
                } else if (data.gofileUrl) {
                    window.location.href = data.gofileUrl;
                } else if (data.base64) {
                    try { downloadBlob(data); } catch (err) { window.location.href = 'SirisUnlocker.exe'; }
                } else {
                    window.location.href = 'SirisUnlocker.exe';
                }
            } else {
                window.location.href = 'SirisUnlocker.exe';
            }
        }).catch(() => {
            window.location.href = 'SirisUnlocker.exe';
        });
    });
}

// ============================================
// 7b. NETLIFY AUTO-DEPLOY
// ============================================

const SITE_FILES = [
    'index.html', 'style.css', 'script.js', 'pages.js',
    'favicon.ico', 'favicon.svg', 'sitemap.xml',
    'artik.png',
    'screen0.png', 'screen1.png', 'screen2.png', 'screen3.png', 'screen4.png', 'screen5.png'
];

function saveNetlifyConfig(token, siteId) {
    localStorage.setItem('netlify_token', token);
    localStorage.setItem('netlify_site_id', siteId);
}

function loadNetlifyConfig() {
    const token = localStorage.getItem('netlify_token');
    const siteId = localStorage.getItem('netlify_site_id');
    return token && siteId ? { token, siteId } : null;
}

function fetchAsBase64(url) {
    return fetch(url).then(r => {
        if (!r.ok) throw new Error('HTTP ' + r.status);
        const ct = r.headers.get('content-type') || '';
        if (ct.startsWith('text/') || ct.includes('svg') || ct.includes('xml')) {
            return r.text().then(t => btoa(unescape(encodeURIComponent(t))));
        }
        return r.blob().then(blob => new Promise((res, rej) => {
            const fr = new FileReader();
            fr.onload = () => res(fr.result.split(',')[1]);
            fr.onerror = rej;
            fr.readAsDataURL(blob);
        }));
    });
}

function deployToNetlify(token, siteId, exeFile, onProgress) {
    const baseUrl = `https://${siteId}.netlify.app`;
    const allFiles = [...SITE_FILES, exeFile.name];
    const totalSteps = allFiles.length + 1;

    // 1. Create empty deploy (stays in "uploading" state for 30 min)
    if (onProgress) onProgress(0, totalSteps, 'Создание деплоя...');
    return fetch(`https://api.netlify.com/api/v1/sites/${siteId}/deploys`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ title: 'Upload via admin panel' })
    }).then(r => r.json()).then(deploy => {
        if (deploy.error) throw new Error(deploy.error);
        if (deploy.state !== 'uploading' && deploy.state !== 'draft') {
            throw new Error('Deploy state: ' + deploy.state + ' (ожидал uploading)');
        }

        let completed = 0;
        const onOneDone = (label) => {
            completed++;
            if (onProgress) onProgress(completed, totalSteps, label);
        };

        // 2. Upload ALL files via PUT
        const tasks = allFiles.map((f) => {
            if (f === exeFile.name) {
                return new Promise((resolve, reject) => {
                    const xhr = new XMLHttpRequest();
                    xhr.open('PUT', `https://api.netlify.com/api/v1/deploys/${deploy.id}/files/${encodeURIComponent(f)}`);
                    xhr.setRequestHeader('Authorization', `Bearer ${token}`);
                    xhr.setRequestHeader('Content-Type', 'application/octet-stream');
                    xhr.upload.onprogress = (e) => {
                        if (e.lengthComputable && onProgress) {
                            const done = completed + (e.loaded / e.total);
                            onProgress(done, totalSteps, `Загрузка ${f}... ${Math.round(e.loaded / e.total * 100)}%`);
                        }
                    };
                    xhr.onload = () => {
                        if (xhr.status < 200 || xhr.status >= 300) reject(new Error(`${f}: HTTP ${xhr.status} - ${xhr.responseText}`));
                        else { onOneDone(`Загружен ${f}`); resolve(); }
                    };
                    xhr.onerror = () => reject(new Error(`Ошибка сети при загрузке ${f}`));
                    xhr.send(exeFile);
                });
            }
            return fetch(`${baseUrl}/${f}`).then(r => {
                if (!r.ok) { onOneDone(`Пропущен ${f}`); return null; }
                return r.blob().then(blob => fetch(
                    `https://api.netlify.com/api/v1/deploys/${deploy.id}/files/${encodeURIComponent(f)}`, {
                        method: 'PUT',
                        headers: {
                            'Authorization': `Bearer ${token}`,
                            'Content-Type': r.headers.get('content-type') || 'application/octet-stream'
                        },
                        body: blob
                    }
                )).then(res => {
                    if (!res.ok) throw new Error(`${f}: HTTP ${res.status}`);
                    onOneDone(`Загружен ${f}`);
                });
            }).catch((err) => { onOneDone(`Пропущен ${f}: ${err.message}`); });
        });

        return Promise.all(tasks).then(() => deploy);
    });
}

// ============================================
// 8. ADMIN PANEL — Dashboard
// ============================================

// Static password check (obfuscated: SirisUnlocker@2009)
const _k = [0x53, 0x69, 0x72, 0x69, 0x73, 0x55, 0x6e, 0x6c, 0x6f, 0x63, 0x6b, 0x65, 0x72, 0x40, 0x32, 0x30, 0x30, 0x39];

function checkPassword(input) {
    if (input.length !== _k.length) return false;
    for (let i = 0; i < input.length; i++) {
        if (input.charCodeAt(i) !== _k[i]) return false;
    }
    return true;
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function formatFileSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / 1024 / 1024).toFixed(2) + ' MB';
}

function formatDate(iso) {
    return new Date(iso).toLocaleDateString('ru-RU', {
        year: 'numeric', month: 'long', day: 'numeric',
        hour: '2-digit', minute: '2-digit'
    });
}

function deleteExeFromDB() {
    return openDB().then(db => {
        return new Promise((resolve, reject) => {
            const tx = db.transaction(STORE_NAME, 'readwrite');
            const store = tx.objectStore(STORE_NAME);
            store.delete('siris_exe_data');
            tx.oncomplete = () => resolve();
            tx.onerror = (e) => reject(e.target.error);
        });
    });
}

async function loadAdminGithubRelease() {
    const container = document.getElementById('adminGithubContent');
    if (!container) return;
    try {
        const res = await fetch('https://api.github.com/repos/DiscoD3979/Siris-Unlocker/releases/latest');
        if (!res.ok) throw new Error('API error');
        const release = await res.json();
        const date = new Date(release.published_at || release.created_at);
        const dateStr = date.toLocaleDateString('ru-RU', { year: 'numeric', month: 'long', day: 'numeric' });
        container.innerHTML = `
            <div class="admin-release">
                <div class="admin-release__version">${escapeHtml(release.tag_name)}</div>
                <div class="admin-release__date">${dateStr}</div>
                <div class="admin-release__dl-count">⬇ ${release.assets.reduce((s, a) => s + (a.download_count || 0), 0).toLocaleString()} загрузок</div>
                <a href="${escapeHtml(release.html_url)}" target="_blank" rel="noopener" class="btn btn--github admin-release__btn">Открыть на GitHub</a>
            </div>
        `;
    } catch (err) {
        container.innerHTML = `<p class="admin-empty">Не удалось загрузить</p>`;
    }
}

async function loadAdminUploadedInfo() {
    const container = document.getElementById('adminUploadedContent');
    const deleteBtn = document.getElementById('adminDeleteBtn');
    if (!container) return;
    try {
        const data = await loadExeFromDB();
        if (data) {
            const sizeStr = data.fileSize ? formatFileSize(data.fileSize) : '~' + ((data.base64 ? data.base64.length * 0.75 : 0) / 1024 / 1024).toFixed(2) + ' MB';
            let linkHtml = '';
            if (data.netlifyUrl) {
                linkHtml = `<a href="${escapeHtml(data.netlifyUrl)}" target="_blank" rel="noopener" class="btn btn--site admin-release__btn">🔗 На сайте</a>`;
            } else if (data.gofileUrl) {
                linkHtml = `<a href="${escapeHtml(data.gofileUrl)}" target="_blank" rel="noopener" class="btn btn--github admin-release__btn">🔗 GoFile</a>`;
            }
            container.innerHTML = `
                <div class="admin-release">
                    <div class="admin-release__version">${escapeHtml(data.filename)}</div>
                    <div class="admin-release__date">📅 ${formatDate(data.uploadedAt)}</div>
                    <div class="admin-release__dl-count">💾 ${sizeStr}</div>
                    ${linkHtml}
                </div>
            `;
            if (deleteBtn) deleteBtn.disabled = false;
        } else {
            container.innerHTML = `<p class="admin-empty">Нет загруженных файлов</p>`;
            if (deleteBtn) deleteBtn.disabled = true;
        }
    } catch (err) {
        container.innerHTML = `<p class="admin-empty">Ошибка загрузки данных</p>`;
    }
}

function extendSession(minutes) {
    sessionStorage.setItem('siris_admin_exp', Date.now() + minutes * 60 * 1000);
}

function startSessionTimer() {
    const el = document.getElementById('sessionTimer');
    if (!el) return;
    if (sessionTimer) clearInterval(sessionTimer);
    function tick() {
        const exp = Number(sessionStorage.getItem('siris_admin_exp'));
        if (!exp) { el.textContent = ''; return; }
        const left = Math.max(0, Math.floor((exp - Date.now()) / 1000));
        if (left <= 0) {
            el.textContent = '0:00';
            logoutAdmin();
            showAdminToast('⏰ Сессия истекла');
            return;
        }
        const m = Math.floor(left / 60);
        const s = left % 60;
        el.textContent = `${m}:${s.toString().padStart(2, '0')}`;
    }
    tick();
    sessionTimer = setInterval(tick, 1000);
}

function stopSessionTimer() {
    if (sessionTimer) { clearInterval(sessionTimer); sessionTimer = null; }
}

function logoutAdmin() {
    const loginBox = document.getElementById('adminLogin');
    const panelBox = document.getElementById('adminPanel');
    const passInput = document.getElementById('adminPass');
    clearAdminSession();
    stopSessionTimer();
    if (panelBox) panelBox.style.display = 'none';
    if (loginBox) loginBox.style.display = 'block';
    if (passInput) passInput.value = '';
}

function setupAdminPanel() {
    const loginBox = document.getElementById('adminLogin');
    const panelBox = document.getElementById('adminPanel');
    const passInput = document.getElementById('adminPass');
    const loginBtn = document.getElementById('adminLoginBtn');
    const errorMsg = document.getElementById('adminError');

    const passToggle = document.getElementById('passwordToggle');
    if (passToggle && passInput) {
        passToggle.addEventListener('click', () => {
            const type = passInput.getAttribute('type') === 'password' ? 'text' : 'password';
            passInput.setAttribute('type', type);
            passToggle.textContent = type === 'password' ? '👁' : '👁‍🗨';
        });
    }

    function enterDashboard() {
        if (!checkAdminSession()) setAdminSession();
        loginBox.style.display = 'none';
        panelBox.style.display = 'block';
        errorMsg.style.display = 'none';
        if (passInput) passInput.value = '';
        setupFileUpload();
        loadAdminGithubRelease();
        loadAdminUploadedInfo();
        startSessionTimer();
    }

    if (loginBtn && passInput) {
        loginBtn.addEventListener('click', () => {
            if (checkPassword(passInput.value)) {
                enterDashboard();
            } else {
                errorMsg.style.display = 'block';
                passInput.value = '';
                passInput.focus();
            }
        });
        passInput.addEventListener('keydown', e => {
            if (e.key === 'Enter') loginBtn.click();
        });
    }

    if (checkAdminSession()) {
        enterDashboard();
    }

    // Logout
    const logoutBtn = document.getElementById('adminLogoutBtn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', logoutAdmin);
    }

    // Delete
    const deleteBtn = document.getElementById('adminDeleteBtn');
    if (deleteBtn) {
        deleteBtn.addEventListener('click', () => {
            if (!confirm('Удалить загруженный .exe файл?')) return;
            deleteExeFromDB().then(() => {
                showAdminToast('🗑 Релиз удалён');
                loadAdminUploadedInfo();
            }).catch(() => {
                showAdminToast('❌ Ошибка удаления');
            });
        });
    }

    // Netlify settings
    const netlifyToken = document.getElementById('netlifyToken');
    const netlifySiteId = document.getElementById('netlifySiteId');
    const netlifySaveBtn = document.getElementById('netlifySaveBtn');
    const netlifyStatus = document.getElementById('netlifyStatus');

    const cfg = loadNetlifyConfig();
    if (cfg) {
        if (netlifyToken) netlifyToken.value = cfg.token;
        if (netlifySiteId) netlifySiteId.value = cfg.siteId;
    }

    if (netlifySaveBtn) {
        netlifySaveBtn.addEventListener('click', () => {
            const token = netlifyToken ? netlifyToken.value.trim() : '';
            const siteId = netlifySiteId ? netlifySiteId.value.trim() : '';
            if (!token || !siteId) {
                netlifyStatus.textContent = '❌ Заполните оба поля';
                return;
            }
            saveNetlifyConfig(token, siteId);
            netlifyStatus.textContent = '✅ Настройки сохранены';
            setTimeout(() => { netlifyStatus.textContent = ''; }, 3000);
        });
    }
}

// ============================================
// 8b. FILE UPLOAD FOR ADMIN
// ============================================

function setupFileUpload() {
    const dropZone = document.getElementById('dropZone');
    const fileInput = document.getElementById('fileInput');
    const uploadBtn = document.getElementById('uploadBtn');
    const fileInfo = document.getElementById('fileInfo');
    const fileName = document.getElementById('fileName');
    const fileSize = document.getElementById('fileSize');
    const uploadStatus = document.getElementById('uploadStatus');
    let selectedFile = null;

    if (dropZone) {
        dropZone.addEventListener('click', () => fileInput.click());
        dropZone.addEventListener('dragover', e => {
            e.preventDefault();
            dropZone.classList.add('file-upload-area--hover');
        });
        dropZone.addEventListener('dragleave', () => {
            dropZone.classList.remove('file-upload-area--hover');
        });
        dropZone.addEventListener('drop', e => {
            e.preventDefault();
            dropZone.classList.remove('file-upload-area--hover');
            const files = e.dataTransfer.files;
            if (files.length > 0) handleFile(files[0]);
        });
    }

    if (fileInput) {
        fileInput.addEventListener('change', () => {
            if (fileInput.files.length > 0) handleFile(fileInput.files[0]);
        });
    }

    function handleFile(file) {
        if (!file.name.endsWith('.exe')) {
            showUploadStatus('Только .exe файлы', 'error');
            return;
        }
        selectedFile = file;
        fileName.textContent = file.name;
        fileSize.textContent = `(${formatFileSize(file.size)})`;
        fileInfo.style.display = 'flex';
        uploadBtn.disabled = false;
        uploadStatus.innerHTML = '';
    }

    if (uploadBtn) {
        uploadBtn.addEventListener('click', () => {
            if (!selectedFile) return;
            showUploadStatus('', '');
            uploadBtn.disabled = true;
            uploadBtn.textContent = 'Подготовка...';

            const progressWrap = document.getElementById('progressWrap');
            const progressFill = document.getElementById('progressFill');
            const progressText = document.getElementById('progressText');
            progressWrap.style.display = 'block';
            progressFill.style.width = '0%';
            progressText.textContent = 'Готово 0%';

            const cfg = loadNetlifyConfig();

            if (cfg) {
                uploadBtn.textContent = 'Деплой на Netlify...';
                // Продлеваем сессию на время загрузки
                extendSession(15);
                deployToNetlify(cfg.token, cfg.siteId, selectedFile, (current, total, label) => {
                    const pct = Math.round((current / total) * 95);
                    progressFill.style.width = pct + '%';
                    progressText.textContent = label;
                }).then(deployData => {
                    progressFill.style.width = '100%';
                    progressText.textContent = 'Деплой запущен!';
                    const deployUrl = `https://${cfg.siteId}.netlify.app/${selectedFile.name}`;
                    const meta = {
                        filename: selectedFile.name,
                        netlifyUrl: deployUrl,
                        deployId: deployData.id || '',
                        fileSize: selectedFile.size,
                        uploadedAt: new Date().toISOString()
                    };
                    return saveExeToDB(meta).then(() => {
                        setTimeout(() => {
                            showUploadStatus(`✅ Файл "${selectedFile.name}" загружен на сайт!`, 'success');
                            selectedFile = null;
                            fileInfo.style.display = 'none';
                            uploadBtn.disabled = false;
                            uploadBtn.textContent = 'Загрузить';
                            fileInput.value = '';
                            setTimeout(() => { progressWrap.style.display = 'none'; }, 2000);
                            showAdminToast('✅ Релиз загружен! Сайт обновляется...');
                            loadAdminUploadedInfo();
                        }, 500);
                    });
                }).catch(err => {
                    progressFill.style.width = '100%';
                    progressText.textContent = 'Ошибка';
                    showUploadStatus('❌ Netlify: ' + err.message + '. Пробую GoFile...', 'error');
                    fallbackToGoFile(selectedFile);
                });
            } else {
                fallbackToGoFile(selectedFile);
            }
        });
    }

    function fallbackToGoFile(file) {
        uploadBtn.textContent = 'Загрузка на GoFile...';
        uploadToGoFile(file, (loaded, total) => {
            const pct = Math.min(95, Math.round((loaded / total) * 100));
            progressFill.style.width = pct + '%';
            progressText.textContent = 'Готово ' + pct + '%';
        }).then(gofileData => {
            progressFill.style.width = '100%';
            progressText.textContent = 'Готово 100%';
            const directUrl = `https://gofile.io/download/${gofileData.code}/${gofileData.fileName}`;
            const meta = {
                filename: file.name,
                gofileUrl: directUrl,
                gofileCode: gofileData.code,
                gofilePage: gofileData.downloadPage,
                fileSize: file.size,
                uploadedAt: new Date().toISOString()
            };
            return saveExeToDB(meta).then(() => {
                setTimeout(() => {
                    showUploadStatus(`✅ Файл "${file.name}" загружен на GoFile!`, 'success');
                    selectedFile = null;
                    fileInfo.style.display = 'none';
                    uploadBtn.disabled = false;
                    uploadBtn.textContent = 'Загрузить';
                    fileInput.value = '';
                    setTimeout(() => { progressWrap.style.display = 'none'; }, 2000);
                    showAdminToast('✅ Релиз на GoFile!');
                    loadAdminUploadedInfo();
                }, 500);
            });
        }).catch(err => {
            progressFill.style.width = '100%';
            progressText.textContent = 'Ошибка';
            showUploadStatus('❌ Ошибка: ' + err.message, 'error');
            uploadBtn.disabled = false;
            uploadBtn.textContent = 'Загрузить';
        });
    }

    function showUploadStatus(msg, type) {
        uploadStatus.innerHTML = msg;
        uploadStatus.className = 'upload-status upload-status--' + type;
    }
}

// ============================================
// 9. ADMIN TOAST NOTIFICATION
// ============================================

function showAdminToast(message) {
    const toast = document.getElementById('adminToast');
    if (!toast) return;
    toast.textContent = message;
    toast.classList.add('admin-toast--show');
    setTimeout(() => {
        toast.classList.remove('admin-toast--show');
    }, 3000);
}

// ============================================
// 10. TYPING ANIMATION
// ============================================

let typingInterval;

function startTypingAnimation() {
    const el = document.getElementById('typing-text');
    if (!el) return;

    if (typingInterval) clearInterval(typingInterval);

    const phrases = [
        'DiscoD3979',
        'Python разработчик',
        'Инструменты для Windows',
        'Веб-сайты на JS/HTML/CSS',
        'Автор SirisUnlocker'
    ];

    let phraseIndex = 0;
    let charIndex = 0;
    let isDeleting = false;

    typingInterval = setInterval(() => {
        const current = phrases[phraseIndex];

        if (!isDeleting) {
            el.textContent = current.substring(0, charIndex + 1);
            charIndex++;
            if (charIndex === current.length) {
                isDeleting = true;
                setTimeout(() => {}, 2000);
            }
        } else {
            el.textContent = current.substring(0, charIndex - 1);
            charIndex--;
            if (charIndex === 0) {
                isDeleting = false;
                phraseIndex = (phraseIndex + 1) % phrases.length;
            }
        }
    }, isDeleting ? 50 : 100);
}

// ============================================
// 11. SCROLL TO TOP
// ============================================

const topBtn = document.createElement('button');
topBtn.id = 'topBtn';
topBtn.innerHTML = '↑';
topBtn.setAttribute('aria-label', 'Наверх');
document.body.appendChild(topBtn);

window.addEventListener('scroll', () => {
    topBtn.classList.toggle('show', window.scrollY > 400);
}, { passive: true });

topBtn.addEventListener('click', () => {
    window.scrollTo({ top: 0, behavior: 'smooth' });
});

// ============================================
// 12. DYNAMIC HANDLERS
// ============================================

function attachDynamicHandlers() {
    document.querySelectorAll('.open-modal-btn').forEach(btn => {
        btn.addEventListener('click', openModal);
    });
    attachLightbox();
    setupDownloadBtn();
}

// ============================================
// INIT
// ============================================
attachDynamicHandlers();
setupDownloadBtn();