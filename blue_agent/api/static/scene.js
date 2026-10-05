// scene.js - Three.js 3D cyber-range scene
import { setScene, updateEffects, createAttackBeam, createDefenseBeam, createExplosion, createShieldEffect, createPulse } from './effects.js';

export let scene, camera, renderer;
let nodes = {};
let particles;

// Node positions (cross layout)
const POS_RED = new THREE.Vector3(-8, 0, 0);
const POS_TARGET = new THREE.Vector3(0, 0, 0);
const POS_BLUE = new THREE.Vector3(8, 0, 0);
const POS_GREEN = new THREE.Vector3(0, 0, -8); // Green agent in the background

// Colors
const COLOR_RED = 0xef4444;
const COLOR_TARGET = 0xf59e0b;
const COLOR_BLUE = 0x06b6d4;
const COLOR_GREEN = 0x10b981;

function createNode(position, color, type) {
    const group = new THREE.Group();
    group.position.copy(position);
    
    let mesh;
    
    if (type === 'target') {
        // Center server/app node — rotating cube
        const geometry = new THREE.BoxGeometry(1.5, 1.5, 1.5);
        const material = new THREE.MeshPhongMaterial({ 
            color: color,
            emissive: color,
            emissiveIntensity: 0.25,
            shininess: 100,
            transparent: true,
            opacity: 0.9
        });
        mesh = new THREE.Mesh(geometry, material);
        
        // Add wireframe edges
        const wireGeo = new THREE.EdgesGeometry(geometry);
        const wireMat = new THREE.LineBasicMaterial({ color: 0xffffff, transparent: true, opacity: 0.3 });
        const wire = new THREE.LineSegments(wireGeo, wireMat);
        mesh.add(wire);
        
    } else {
        // Red/Blue spheres
        const geometry = new THREE.SphereGeometry(1, 32, 32);
        const material = new THREE.MeshPhongMaterial({ 
            color: color,
            emissive: color,
            emissiveIntensity: 0.35,
            shininess: 100,
            transparent: true,
            opacity: 0.85
        });
        mesh = new THREE.Mesh(geometry, material);
        
        if (type === 'blue') {
            // Add shield ring around blue agent
            const ringGeo = new THREE.TorusGeometry(1.6, 0.04, 16, 64);
            const ringMat = new THREE.MeshBasicMaterial({ color: color, transparent: true, opacity: 0.5 });
            const ring = new THREE.Mesh(ringGeo, ringMat);
            ring.rotation.x = Math.PI / 2;
            group.add(ring);
            group.ring = ring;
            
            // Second ring at angle
            const ring2 = new THREE.Mesh(
                new THREE.TorusGeometry(1.8, 0.03, 16, 64),
                new THREE.MeshBasicMaterial({ color: color, transparent: true, opacity: 0.3 })
            );
            ring2.rotation.x = Math.PI / 3;
            ring2.rotation.z = Math.PI / 4;
            group.add(ring2);
            group.ring2 = ring2;
        } else if (type === 'green') {
            // Pulsing rings for green agent
            const ringGeo = new THREE.TorusGeometry(1.4, 0.02, 16, 32);
            const ringMat = new THREE.MeshBasicMaterial({ color: color, transparent: true, opacity: 0.6 });
            const ring = new THREE.Mesh(ringGeo, ringMat);
            group.add(ring);
            group.ring = ring;
        } else {
            // Wireframe overlay for red agent
            const wireGeo = new THREE.WireframeGeometry(geometry);
            const wireMat = new THREE.LineBasicMaterial({ color: 0xffffff, transparent: true, opacity: 0.15 });
            const wire = new THREE.LineSegments(wireGeo, wireMat);
            mesh.add(wire);
        }
    }
    
    group.add(mesh);
    group.mesh = mesh;
    
    // Add point light
    const light = new THREE.PointLight(color, 2.5, 12);
    group.add(light);
    group.light = light;
    
    // Add glow sprite
    const spriteMat = new THREE.SpriteMaterial({
        color: color,
        transparent: true,
        opacity: 0.15,
        blending: THREE.AdditiveBlending
    });
    const sprite = new THREE.Sprite(spriteMat);
    sprite.scale.set(5, 5, 1);
    group.add(sprite);
    
    scene.add(group);
    return group;
}

function createBackgroundParticles() {
    const particleCount = 1500;
    const geometry = new THREE.BufferGeometry();
    const positions = new Float32Array(particleCount * 3);
    
    for (let i = 0; i < particleCount * 3; i++) {
        positions[i] = (Math.random() - 0.5) * 50;
    }
    
    geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));
    
    const material = new THREE.PointsMaterial({
        color: 0xffffff,
        size: 0.04,
        transparent: true,
        opacity: 0.4,
        blending: THREE.AdditiveBlending
    });
    
    particles = new THREE.Points(geometry, material);
    scene.add(particles);
}

// Grid floor for depth perception
function createGrid() {
    const gridHelper = new THREE.GridHelper(30, 30, 0x1a1a2e, 0x0d0d1a);
    gridHelper.position.y = -3;
    gridHelper.material.transparent = true;
    gridHelper.material.opacity = 0.3;
    scene.add(gridHelper);
}

function createLabels() {
    const container = document.getElementById('labels-container');
    if (!container) return;
    container.innerHTML = `
        <div id="label-red" class="node-label red">RED AGENT<br><small>Attacker</small></div>
        <div id="label-target" class="node-label amber">TARGET APP<br><small>Vulnerable Sys</small></div>
        <div id="label-blue" class="node-label cyan">BLUE AGENT<br><small>Defender</small></div>
        <div id="label-green" class="node-label green">GREEN AGENT<br><small>Legitimate Users</small></div>
    `;
}

function updateHTMLPositions() {
    const updateLabel = (id, pos3d) => {
        const el = document.getElementById(id);
        if (!el) return;
        
        const pos = pos3d.clone();
        pos.y -= 2; // offset below the node
        pos.project(camera);
        
        const x = (pos.x * .5 + .5) * window.innerWidth;
        const y = (pos.y * -.5 + .5) * window.innerHeight;
        
        el.style.left = `${x}px`;
        el.style.top = `${y}px`;
    };
    
    updateLabel('label-red', nodes.red.position);
    updateLabel('label-target', nodes.target.position);
    updateLabel('label-blue', nodes.blue.position);
    updateLabel('label-green', nodes.green.position);
}

export function init(containerId) {
    const container = document.getElementById(containerId);
    
    // Scene setup
    scene = new THREE.Scene();
    scene.fog = new THREE.FogExp2(0x060a14, 0.025);
    
    // Share scene reference with effects module
    setScene(scene);
    
    // Camera
    camera = new THREE.PerspectiveCamera(45, window.innerWidth / window.innerHeight, 0.1, 1000);
    camera.position.set(0, 6, 22);
    camera.lookAt(0, 0, 0);
    
    // Renderer
    renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setSize(window.innerWidth, window.innerHeight);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.setClearColor(0x000000, 0);
    container.appendChild(renderer.domElement);
    
    // Lighting
    const ambientLight = new THREE.AmbientLight(0x1a1a33, 0.6);
    scene.add(ambientLight);
    
    const directionalLight = new THREE.DirectionalLight(0xffffff, 0.4);
    directionalLight.position.set(5, 10, 7);
    scene.add(directionalLight);
    
    // Nodes
    nodes.red = createNode(POS_RED, COLOR_RED, 'red');
    nodes.target = createNode(POS_TARGET, COLOR_TARGET, 'target');
    nodes.blue = createNode(POS_BLUE, COLOR_BLUE, 'blue');
    nodes.green = createNode(POS_GREEN, COLOR_GREEN, 'green');
    
    // Background
    createBackgroundParticles();
    createGrid();
    
    // Labels
    createLabels();
    
    // Resize handler
    window.addEventListener('resize', onWindowResize, false);
    
    // Start loop
    animate();
}

function onWindowResize() {
    camera.aspect = window.innerWidth / window.innerHeight;
    camera.updateProjectionMatrix();
    renderer.setSize(window.innerWidth, window.innerHeight);
    updateHTMLPositions();
}

function animate(time) {
    requestAnimationFrame(animate);
    
    const t = (time || 0) * 0.001;
    
    // Slow camera orbit
    camera.position.x = Math.sin(t * 0.08) * 22;
    camera.position.z = Math.cos(t * 0.08) * 22;
    camera.position.y = 5 + Math.sin(t * 0.15) * 1.5;
    camera.lookAt(0, 0, 0);
    
    // Node animations
    nodes.red.position.y = Math.sin(t * 1.8) * 0.5;
    nodes.red.mesh.rotation.y = t * 0.5;
    nodes.red.light.intensity = 2.5 + Math.sin(t * 3) * 0.5;
    
    nodes.target.position.y = Math.sin(t * 1.8 + 1) * 0.3;
    nodes.target.mesh.rotation.x = t * 0.3;
    nodes.target.mesh.rotation.y = t * 0.5;
    
    nodes.blue.position.y = Math.sin(t * 1.8 + 2) * 0.5;
    nodes.blue.mesh.rotation.y = -t * 0.4;
    if (nodes.blue.ring) nodes.blue.ring.rotation.z = t * 0.8;
    if (nodes.blue.ring2) nodes.blue.ring2.rotation.z = -t * 0.6;
    nodes.blue.light.intensity = 2.5 + Math.sin(t * 3 + 1) * 0.5;

    nodes.green.position.y = Math.sin(t * 1.5 + 3) * 0.4;
    nodes.green.mesh.rotation.x = t * 0.2;
    if (nodes.green.ring) {
        nodes.green.ring.scale.setScalar(1 + Math.sin(t * 4) * 0.1);
    }
    nodes.green.light.intensity = 2.0 + Math.sin(t * 2) * 0.5;
    
    // Background particles
    if (particles) {
        particles.rotation.y = t * 0.03;
        particles.rotation.x = Math.sin(t * 0.02) * 0.1;
    }
    
    // Update labels
    updateHTMLPositions();
    
    // Effects
    updateEffects(time || performance.now());
    
    renderer.render(scene, camera);
}

// Public API for app.js
export function fireAttack() {
    createAttackBeam(nodes.red.position, nodes.target.position, COLOR_RED, 1500, () => {
        createExplosion(nodes.target.position, COLOR_RED, 30);
        createPulse(nodes.target.position, COLOR_RED);
        // Flash target red briefly
        nodes.target.light.color.setHex(COLOR_RED);
        nodes.target.light.intensity = 6;
        setTimeout(() => {
            nodes.target.light.color.setHex(COLOR_TARGET);
            nodes.target.light.intensity = 2.5;
        }, 300);
    });
}

export function fireDefense() {
    createDefenseBeam(nodes.blue.position, nodes.target.position, COLOR_BLUE, 800, () => {
        createShieldEffect(nodes.target.position, COLOR_BLUE, 1200);
        createPulse(nodes.target.position, 0x06b6d4);
        // Flash target green briefly
        nodes.target.light.color.setHex(0x06b6d4);
        nodes.target.light.intensity = 5;
        setTimeout(() => {
            nodes.target.light.color.setHex(COLOR_TARGET);
            nodes.target.light.intensity = 2.5;
        }, 400);
    });
}

export function fireBenign() {
    // A soft, slower beam from the green agent
    createDefenseBeam(nodes.green.position, nodes.target.position, COLOR_GREEN, 2000, () => {
        // Soft pulse on arrival
        createPulse(nodes.target.position, COLOR_GREEN);
    });
}
