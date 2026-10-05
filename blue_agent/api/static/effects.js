// effects.js - Handles particle effects and animations
// NOTE: Scene reference is set by scene.js via setScene()

let _scene = null;
const activeEffects = [];

export function setScene(sceneRef) {
    _scene = sceneRef;
}

// Helper: Quadratic Bezier Curve
function getQuadraticBezierPoint(t, p0, p1, p2) {
    const u = 1 - t;
    const tt = t * t;
    const uu = u * u;
    
    const x = uu * p0.x + 2 * u * t * p1.x + tt * p2.x;
    const y = uu * p0.y + 2 * u * t * p1.y + tt * p2.y;
    const z = uu * p0.z + 2 * u * t * p1.z + tt * p2.z;
    
    return new THREE.Vector3(x, y, z);
}

export function createAttackBeam(startPos, endPos, color, duration = 1500, onComplete) {
    if (!_scene) return;
    
    const geometry = new THREE.SphereGeometry(0.15, 8, 8);
    const material = new THREE.MeshBasicMaterial({ 
        color: color,
        transparent: true,
        opacity: 0.9
    });
    
    const projectile = new THREE.Mesh(geometry, material);
    
    // Glow light on projectile
    const light = new THREE.PointLight(color, 2, 4);
    projectile.add(light);
    
    _scene.add(projectile);
    
    // Trail particles
    const trailGeo = new THREE.BufferGeometry();
    const trailCount = 15;
    const trailPositions = new Float32Array(trailCount * 3);
    trailGeo.setAttribute('position', new THREE.BufferAttribute(trailPositions, 3));
    const trailMat = new THREE.PointsMaterial({
        color: color,
        size: 0.08,
        transparent: true,
        opacity: 0.6,
        blending: THREE.AdditiveBlending
    });
    const trail = new THREE.Points(trailGeo, trailMat);
    _scene.add(trail);
    const trailHistory = [];
    
    // Control points for curved path
    const midPoint = new THREE.Vector3().addVectors(startPos, endPos).multiplyScalar(0.5);
    midPoint.y += 2 + Math.random() * 2;
    midPoint.z += (Math.random() - 0.5) * 3;
    
    const startTime = performance.now();
    
    const effect = {
        update: (time) => {
            const elapsed = time - startTime;
            const t = Math.min(elapsed / duration, 1);
            const easeT = t < 0.5 ? 2 * t * t : -1 + (4 - 2 * t) * t;
            
            const pos = getQuadraticBezierPoint(easeT, startPos, midPoint, endPos);
            projectile.position.copy(pos);
            
            // Update trail
            trailHistory.unshift(pos.clone());
            if (trailHistory.length > trailCount) trailHistory.pop();
            const arr = trailGeo.attributes.position.array;
            for (let i = 0; i < trailCount; i++) {
                if (i < trailHistory.length) {
                    arr[i*3] = trailHistory[i].x;
                    arr[i*3+1] = trailHistory[i].y;
                    arr[i*3+2] = trailHistory[i].z;
                }
            }
            trailGeo.attributes.position.needsUpdate = true;
            
            if (t >= 1) {
                _scene.remove(projectile);
                _scene.remove(trail);
                geometry.dispose(); material.dispose();
                trailGeo.dispose(); trailMat.dispose();
                if (onComplete) onComplete();
                return false;
            }
            return true;
        }
    };
    
    activeEffects.push(effect);
}

export function createDefenseBeam(startPos, endPos, color, duration = 800, onComplete) {
    if (!_scene) return;
    
    const geometry = new THREE.SphereGeometry(0.12, 8, 8);
    const material = new THREE.MeshBasicMaterial({ 
        color: color,
        transparent: true,
        opacity: 0.9
    });
    const projectile = new THREE.Mesh(geometry, material);
    
    const light = new THREE.PointLight(color, 1.5, 3);
    projectile.add(light);
    
    _scene.add(projectile);
    
    // Straighter path for defense beam
    const midPoint = new THREE.Vector3().addVectors(startPos, endPos).multiplyScalar(0.5);
    midPoint.y += 0.8;
    
    const startTime = performance.now();
    
    const effect = {
        update: (time) => {
            const elapsed = time - startTime;
            const t = Math.min(elapsed / duration, 1);
            
            const pos = getQuadraticBezierPoint(t, startPos, midPoint, endPos);
            projectile.position.copy(pos);
            
            if (t >= 1) {
                _scene.remove(projectile);
                geometry.dispose();
                material.dispose();
                if (onComplete) onComplete();
                return false;
            }
            return true;
        }
    };
    
    activeEffects.push(effect);
}

export function createExplosion(position, color, particleCount = 30) {
    if (!_scene) return;
    
    const geometry = new THREE.BufferGeometry();
    const positions = new Float32Array(particleCount * 3);
    const velocities = [];
    
    for (let i = 0; i < particleCount; i++) {
        positions[i*3] = position.x;
        positions[i*3+1] = position.y;
        positions[i*3+2] = position.z;
        
        const theta = Math.random() * Math.PI * 2;
        const phi = Math.acos(Math.random() * 2 - 1);
        const speed = 0.05 + Math.random() * 0.12;
        
        velocities.push({
            x: Math.sin(phi) * Math.cos(theta) * speed,
            y: Math.sin(phi) * Math.sin(theta) * speed,
            z: Math.cos(phi) * speed
        });
    }
    
    geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));
    
    const material = new THREE.PointsMaterial({
        color: color,
        size: 0.2,
        transparent: true,
        opacity: 1,
        blending: THREE.AdditiveBlending
    });
    
    const particles = new THREE.Points(geometry, material);
    _scene.add(particles);
    
    const startTime = performance.now();
    const duration = 1200;
    
    const effect = {
        update: (time) => {
            const elapsed = time - startTime;
            const t = elapsed / duration;
            
            if (t >= 1) {
                _scene.remove(particles);
                geometry.dispose();
                material.dispose();
                return false;
            }
            
            const posAttr = geometry.attributes.position;
            const arr = posAttr.array;
            
            for (let i = 0; i < particleCount; i++) {
                arr[i*3] += velocities[i].x;
                arr[i*3+1] += velocities[i].y;
                arr[i*3+2] += velocities[i].z;
                velocities[i].y -= 0.001;
            }
            
            posAttr.needsUpdate = true;
            material.opacity = 1 - (t * t);
            
            return true;
        }
    };
    
    activeEffects.push(effect);
}

export function createShieldEffect(position, color, duration = 1200) {
    if (!_scene) return;
    
    const geometry = new THREE.SphereGeometry(1.8, 32, 32);
    const material = new THREE.MeshBasicMaterial({
        color: color,
        transparent: true,
        opacity: 0.4,
        wireframe: true,
        blending: THREE.AdditiveBlending
    });
    
    const shield = new THREE.Mesh(geometry, material);
    shield.position.copy(position);
    _scene.add(shield);
    
    // Also add a solid inner glow
    const innerGeo = new THREE.SphereGeometry(1.6, 24, 24);
    const innerMat = new THREE.MeshBasicMaterial({
        color: color,
        transparent: true,
        opacity: 0.08,
        blending: THREE.AdditiveBlending
    });
    const innerShield = new THREE.Mesh(innerGeo, innerMat);
    innerShield.position.copy(position);
    _scene.add(innerShield);
    
    const startTime = performance.now();
    
    const effect = {
        update: (time) => {
            const elapsed = time - startTime;
            const t = elapsed / duration;
            
            if (t >= 1) {
                _scene.remove(shield);
                _scene.remove(innerShield);
                geometry.dispose(); material.dispose();
                innerGeo.dispose(); innerMat.dispose();
                return false;
            }
            
            const scale = 1 + (Math.sin(t * Math.PI * 2) * 0.15);
            shield.scale.set(scale, scale, scale);
            material.opacity = 0.4 * (1 - t);
            innerMat.opacity = 0.08 * (1 - t);
            
            return true;
        }
    };
    
    activeEffects.push(effect);
}

export function createPulse(position, color) {
    if (!_scene) return;
    
    const geometry = new THREE.RingGeometry(0.5, 0.6, 32);
    const material = new THREE.MeshBasicMaterial({
        color: color,
        transparent: true,
        opacity: 0.6,
        side: THREE.DoubleSide,
        blending: THREE.AdditiveBlending
    });
    
    const ring = new THREE.Mesh(geometry, material);
    ring.position.copy(position);
    ring.rotation.x = Math.PI / 2;
    _scene.add(ring);
    
    const startTime = performance.now();
    const duration = 800;
    
    const effect = {
        update: (time) => {
            const elapsed = time - startTime;
            const t = elapsed / duration;
            
            if (t >= 1) {
                _scene.remove(ring);
                geometry.dispose();
                material.dispose();
                return false;
            }
            
            const s = 1 + t * 4;
            ring.scale.set(s, s, s);
            material.opacity = 0.6 * (1 - t);
            
            return true;
        }
    };
    
    activeEffects.push(effect);
}

export function updateEffects(time) {
    for (let i = activeEffects.length - 1; i >= 0; i--) {
        const keep = activeEffects[i].update(time);
        if (!keep) {
            activeEffects.splice(i, 1);
        }
    }
}
