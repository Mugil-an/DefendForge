import React, { useEffect, useRef, useState } from 'react';
import * as THREE from 'three';
import { Camera, Eye, RotateCw, ShieldCheck, Zap, Crosshair, Shield } from 'lucide-react';

export default function ThreeArenaScene({ currentAttack, currentDefense, isRunning }) {
  const mountRef = useRef(null);
  const sceneRef = useRef(null);
  const rendererRef = useRef(null);
  const cameraRef = useRef(null);
  const animFrameRef = useRef(null);

  // Nodes & FX references
  const redGroupRef = useRef(null);
  const targetGroupRef = useRef(null);
  const blueGroupRef = useRef(null);
  const shieldMeshRef = useRef(null);
  const shieldOuterMeshRef = useRef(null);
  const defenseTetherRef = useRef(null);
  const activeEffectsRef = useRef([]);

  // Camera & view mode
  const [viewMode, setViewMode] = useState('cinematic'); // 'cinematic' | 'front' | 'overhead' | 'red_eye' | 'blue_eye'
  const isDraggingRef = useRef(false);
  const previousMousePosRef = useRef({ x: 0, y: 0 });
  const cameraAngleRef = useRef({ theta: 0, phi: Math.PI / 6, radius: 18 });

  // Floating text / combat log overlay in 3D
  const [floatingCombatText, setFloatingCombatText] = useState(null);

  useEffect(() => {
    const container = mountRef.current;
    if (!container) return;

    // 1. Scene & Camera Setup
    const width = container.clientWidth || 800;
    const height = 400;

    const scene = new THREE.Scene();
    sceneRef.current = scene;
    scene.fog = new THREE.FogExp2(0x07090e, 0.022);

    const camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 1000);
    cameraRef.current = camera;
    camera.position.set(0, 5, 18);
    camera.lookAt(0, 0, 0);

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    rendererRef.current = renderer;
    renderer.setSize(width, height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.setClearColor(0x000000, 0);
    container.replaceChildren(renderer.domElement);

    // 2. Lighting
    const ambientLight = new THREE.AmbientLight(0xffffff, 0.65);
    scene.add(ambientLight);

    const dirLight = new THREE.DirectionalLight(0x38bdf8, 1.3);
    dirLight.position.set(5, 14, 8);
    scene.add(dirLight);

    // 3. Cyber Grid Floor with dual layers
    const gridHelper = new THREE.GridHelper(36, 36, 0x1e293b, 0x0f172a);
    gridHelper.position.y = -3.2;
    gridHelper.material.opacity = 0.55;
    gridHelper.material.transparent = true;
    scene.add(gridHelper);

    // 4. Background Starfield / Particle Cloud
    const particleCount = 850;
    const particleGeo = new THREE.BufferGeometry();
    const particlePos = new Float32Array(particleCount * 3);
    for (let i = 0; i < particleCount * 3; i += 3) {
      particlePos[i] = (Math.random() - 0.5) * 60;
      particlePos[i + 1] = (Math.random() - 0.5) * 28 + 2;
      particlePos[i + 2] = (Math.random() - 0.5) * 40 - 5;
    }
    particleGeo.setAttribute('position', new THREE.BufferAttribute(particlePos, 3));
    const particleMat = new THREE.PointsMaterial({
      color: 0x94a3b8,
      size: 0.08,
      transparent: true,
      opacity: 0.45,
      blending: THREE.AdditiveBlending,
    });
    const starfield = new THREE.Points(particleGeo, particleMat);
    scene.add(starfield);

    // -------------------------------------------------------------
    // 5. NODE CREATION
    // -------------------------------------------------------------

    // 🔴 RED AGENT (Left Node, x = -7.5)
    const redGroup = new THREE.Group();
    redGroup.position.set(-7.5, 0, 0);
    redGroupRef.current = redGroup;

    // Core Octahedron
    const redCoreGeo = new THREE.OctahedronGeometry(1.25, 0);
    const redCoreMat = new THREE.MeshPhongMaterial({
      color: 0xf43f5e,
      emissive: 0xf43f5e,
      emissiveIntensity: 0.6,
      shininess: 90,
    });
    const redCore = new THREE.Mesh(redCoreGeo, redCoreMat);
    redGroup.add(redCore);

    // Wireframe Outer Cage
    const redWireGeo = new THREE.IcosahedronGeometry(1.7, 1);
    const redWireMat = new THREE.MeshBasicMaterial({
      color: 0xf43f5e,
      wireframe: true,
      transparent: true,
      opacity: 0.35,
    });
    const redCage = new THREE.Mesh(redWireGeo, redWireMat);
    redGroup.add(redCage);

    // Orbiting Attack Satellite Drones
    const redDroneGeo = new THREE.BoxGeometry(0.28, 0.28, 0.28);
    const redDroneMat = new THREE.MeshBasicMaterial({ color: 0xff6b81 });
    const redDrone1 = new THREE.Mesh(redDroneGeo, redDroneMat);
    const redDrone2 = new THREE.Mesh(redDroneGeo, redDroneMat);
    redDrone1.position.set(2.2, 0, 0);
    redDrone2.position.set(-2.2, 0, 0);
    redGroup.add(redDrone1);
    redGroup.add(redDrone2);

    const redLight = new THREE.PointLight(0xf43f5e, 2.5, 10);
    redGroup.add(redLight);
    scene.add(redGroup);

    // 🟡 TARGET CONTAINER (Center Node, x = 0)
    const targetGroup = new THREE.Group();
    targetGroup.position.set(0, 0, 0);
    targetGroupRef.current = targetGroup;

    // Server Chassis (Box with beveled look)
    const targetCoreGeo = new THREE.BoxGeometry(1.8, 2.0, 1.8);
    const targetCoreMat = new THREE.MeshPhongMaterial({
      color: 0x0f172a,
      emissive: 0xf59e0b,
      emissiveIntensity: 0.25,
      shininess: 85,
    });
    const targetCore = new THREE.Mesh(targetCoreGeo, targetCoreMat);
    targetGroup.add(targetCore);

    // Wireframe Edges
    const targetEdges = new THREE.LineSegments(
      new THREE.EdgesGeometry(targetCoreGeo),
      new THREE.LineBasicMaterial({ color: 0xf59e0b, transparent: true, opacity: 0.85 })
    );
    targetGroup.add(targetEdges);

    // Server Rack Status Ring
    const ringGeo = new THREE.TorusGeometry(1.55, 0.04, 16, 64);
    const ringMat = new THREE.MeshBasicMaterial({ color: 0x38bdf8, transparent: true, opacity: 0.75 });
    const targetRing = new THREE.Mesh(ringGeo, ringMat);
    targetRing.rotation.x = Math.PI / 2;
    targetGroup.add(targetRing);

    // Inner Defense Shield Sphere
    const shieldGeo = new THREE.SphereGeometry(2.35, 32, 32);
    const shieldMat = new THREE.MeshPhongMaterial({
      color: 0x06b6d4,
      emissive: 0x06b6d4,
      emissiveIntensity: 0.2,
      transparent: true,
      opacity: 0.15,
      wireframe: true,
      depthWrite: false,
    });
    const shieldMesh = new THREE.Mesh(shieldGeo, shieldMat);
    shieldMeshRef.current = shieldMesh;
    targetGroup.add(shieldMesh);

    // Outer Hexagonal Glow Field
    const outerShieldGeo = new THREE.IcosahedronGeometry(2.6, 2);
    const outerShieldMat = new THREE.MeshBasicMaterial({
      color: 0x06b6d4,
      transparent: true,
      opacity: 0.08,
      wireframe: true,
      depthWrite: false,
    });
    const outerShieldMesh = new THREE.Mesh(outerShieldGeo, outerShieldMat);
    shieldOuterMeshRef.current = outerShieldMesh;
    targetGroup.add(outerShieldMesh);

    const targetLight = new THREE.PointLight(0xf59e0b, 1.8, 8);
    targetGroup.add(targetLight);
    scene.add(targetGroup);

    // 🔵 BLUE AGENT (Right Node, x = 7.5)
    const blueGroup = new THREE.Group();
    blueGroup.position.set(7.5, 0, 0);
    blueGroupRef.current = blueGroup;

    // Guardian Core (Icosahedron)
    const blueCoreGeo = new THREE.IcosahedronGeometry(1.3, 0);
    const blueCoreMat = new THREE.MeshPhongMaterial({
      color: 0x06b6d4,
      emissive: 0x06b6d4,
      emissiveIntensity: 0.65,
      shininess: 100,
    });
    const blueCore = new THREE.Mesh(blueCoreGeo, blueCoreMat);
    blueGroup.add(blueCore);

    // Rotating Orbital Shield Ring 1
    const blueRing1Geo = new THREE.TorusGeometry(1.85, 0.05, 16, 64);
    const blueRing1Mat = new THREE.MeshBasicMaterial({ color: 0x38bdf8, transparent: true, opacity: 0.85 });
    const blueRing1 = new THREE.Mesh(blueRing1Geo, blueRing1Mat);
    blueRing1.rotation.x = Math.PI / 4;
    blueGroup.add(blueRing1);

    // Rotating Orbital Shield Ring 2
    const blueRing2Geo = new THREE.TorusGeometry(2.1, 0.04, 16, 64);
    const blueRing2Mat = new THREE.MeshBasicMaterial({ color: 0x10b981, transparent: true, opacity: 0.7 });
    const blueRing2 = new THREE.Mesh(blueRing2Geo, blueRing2Mat);
    blueRing2.rotation.y = Math.PI / 3;
    blueGroup.add(blueRing2);

    const blueLight = new THREE.PointLight(0x06b6d4, 2.8, 10);
    blueGroup.add(blueLight);
    scene.add(blueGroup);

    // Cyber Defense Tether Line (Subtle persistent link between Blue and Target)
    const tetherPoints = [new THREE.Vector3(7.5, 0, 0), new THREE.Vector3(0, 0, 0)];
    const tetherGeo = new THREE.BufferGeometry().setFromPoints(tetherPoints);
    const tetherMat = new THREE.LineDashedMaterial({
      color: 0x06b6d4,
      dashSize: 0.4,
      gapSize: 0.2,
      transparent: true,
      opacity: 0.35,
    });
    const defenseTether = new THREE.Line(tetherGeo, tetherMat);
    defenseTether.computeLineDistances();
    defenseTetherRef.current = defenseTether;
    scene.add(defenseTether);

    // -------------------------------------------------------------
    // 6. ANIMATION LOOP
    // -------------------------------------------------------------
    let clock = new THREE.Clock();

    const animate = () => {
      animFrameRef.current = requestAnimationFrame(animate);
      const elapsed = clock.getElapsedTime();

      // Idle Node Hover & Rotation
      if (redGroupRef.current) {
        redGroupRef.current.position.y = Math.sin(elapsed * 1.8) * 0.22;
        redCore.rotation.y = elapsed * 0.9;
        redCore.rotation.x = elapsed * 0.45;
        redCage.rotation.y = -elapsed * 0.6;
        redDrone1.position.x = Math.cos(elapsed * 2.5) * 2.2;
        redDrone1.position.z = Math.sin(elapsed * 2.5) * 2.2;
        redDrone2.position.x = -Math.cos(elapsed * 2.5) * 2.2;
        redDrone2.position.z = -Math.sin(elapsed * 2.5) * 2.2;
      }

      if (targetGroupRef.current) {
        targetGroupRef.current.position.y = Math.sin(elapsed * 1.2 + 1) * 0.15;
        targetCore.rotation.y = elapsed * 0.35;
        targetRing.rotation.z = elapsed * 0.6;
        if (shieldMeshRef.current) {
          shieldMeshRef.current.rotation.y = -elapsed * 0.5;
        }
        if (shieldOuterMeshRef.current) {
          shieldOuterMeshRef.current.rotation.x = elapsed * 0.3;
          shieldOuterMeshRef.current.rotation.y = elapsed * 0.4;
        }
      }

      if (blueGroupRef.current) {
        blueGroupRef.current.position.y = Math.sin(elapsed * 1.6 + 2) * 0.22;
        blueCore.rotation.y = -elapsed * 0.8;
        blueRing1.rotation.z = elapsed * 1.2;
        blueRing2.rotation.x = elapsed * 0.9;
      }

      // Update Active Beams & Particle FX
      const activeEffects = activeEffectsRef.current;
      for (let i = activeEffects.length - 1; i >= 0; i--) {
        const effect = activeEffects[i];
        effect.progress += effect.speed;

        if (effect.type === 'attack_beam') {
          // Move plasma projectile along quadratic bezier
          const t = Math.min(1, effect.progress);
          const p0 = effect.start;
          const p1 = effect.control;
          const p2 = effect.end;

          const x = (1 - t) * (1 - t) * p0.x + 2 * (1 - t) * t * p1.x + t * t * p2.x;
          const y = (1 - t) * (1 - t) * p0.y + 2 * (1 - t) * t * p1.y + t * t * p2.y;
          const z = (1 - t) * (1 - t) * p0.z + 2 * (1 - t) * t * p1.z + t * t * p2.z;
          effect.mesh.position.set(x, y, z);

          // Add trail particle
          if (effect.trail && Math.random() > 0.25) {
            const trailParticle = effect.trail.clone();
            trailParticle.position.set(x + (Math.random() - 0.5) * 0.2, y + (Math.random() - 0.5) * 0.2, z);
            scene.add(trailParticle);
            setTimeout(() => {
              scene.remove(trailParticle);
              trailParticle.geometry.dispose();
              trailParticle.material.dispose();
            }, 260);
          }

          if (t >= 1) {
            // Impact!
            scene.remove(effect.mesh);
            effect.mesh.geometry.dispose();
            effect.mesh.material.dispose();
            activeEffects.splice(i, 1);

            // Trigger shield flare or impact explosion & audio
            triggerImpactEffect(effect.isBlocked, effect.attackType);
          }
        } else if (effect.type === 'defense_beam') {
          // Cyan defense stream from Blue to Target
          const t = Math.min(1, effect.progress);
          effect.mesh.material.opacity = Math.sin(t * Math.PI) * 0.9;
          if (t >= 1) {
            scene.remove(effect.mesh);
            effect.mesh.geometry.dispose();
            effect.mesh.material.dispose();
            activeEffects.splice(i, 1);
          }
        } else if (effect.type === 'explosion') {
          // Particles spreading outward
          const positions = effect.mesh.geometry.attributes.position.array;
          for (let j = 0; j < effect.velocities.length; j++) {
            positions[j * 3] += effect.velocities[j].x;
            positions[j * 3 + 1] += effect.velocities[j].y;
            positions[j * 3 + 2] += effect.velocities[j].z;
          }
          effect.mesh.geometry.attributes.position.needsUpdate = true;
          effect.mesh.material.opacity = (1 - effect.progress) * 0.85;

          if (effect.progress >= 1) {
            scene.remove(effect.mesh);
            effect.mesh.geometry.dispose();
            effect.mesh.material.dispose();
            activeEffects.splice(i, 1);
          }
        }
      }

      // Camera view update
      if (viewMode === 'cinematic' && !isDraggingRef.current) {
        cameraAngleRef.current.theta += 0.003;
        const { theta, phi, radius } = cameraAngleRef.current;
        camera.position.x = radius * Math.sin(phi) * Math.sin(theta);
        camera.position.y = Math.max(3, radius * Math.cos(phi));
        camera.position.z = radius * Math.sin(phi) * Math.cos(theta);
        camera.lookAt(0, 0, 0);
      }

      renderer.render(scene, camera);
    };

    animate();

    // 7. Window & Resize Handling
    const handleResize = () => {
      if (!container || !rendererRef.current || !cameraRef.current) return;
      const newWidth = container.clientWidth;
      const newHeight = 400;
      cameraRef.current.aspect = newWidth / newHeight;
      cameraRef.current.updateProjectionMatrix();
      rendererRef.current.setSize(newWidth, newHeight);
    };

    window.addEventListener('resize', handleResize);

    return () => {
      window.removeEventListener('resize', handleResize);
      if (animFrameRef.current) cancelAnimationFrame(animFrameRef.current);
      if (rendererRef.current && rendererRef.current.domElement) {
        rendererRef.current.domElement.remove();
        rendererRef.current.dispose();
      }
    };
  }, []);

  // -------------------------------------------------------------
  // TRIGGER FX WHEN CURRENT ATTACK / DEFENSE ARRIVES
  // -------------------------------------------------------------
  useEffect(() => {
    if (!currentAttack) return;

    const isBlocked = ['blocked', 'block_ip', 'block_source_ip', 'rate_limit', 'update_security_rule'].includes(
      currentDefense?.action
    );

    fireAttackBeam(currentAttack.attack_type || 'Exploit', isBlocked);
  }, [currentAttack, currentDefense]);

  // Fire red plasma beam from Red Agent to Target
  const fireAttackBeam = (attackType, isBlocked) => {
    const scene = sceneRef.current;
    if (!scene) return;

    // Beam projectile
    const beamGeo = new THREE.SphereGeometry(0.38, 16, 16);
    const beamMat = new THREE.MeshBasicMaterial({
      color: 0xff2255,
      transparent: true,
      opacity: 0.95,
    });
    const beamMesh = new THREE.Mesh(beamGeo, beamMat);
    beamMesh.position.set(-7.5, 0, 0);
    scene.add(beamMesh);

    // Trail particle template
    const trailGeo = new THREE.SphereGeometry(0.12, 8, 8);
    const trailMat = new THREE.MeshBasicMaterial({ color: 0xf43f5e, transparent: true, opacity: 0.65 });
    const trailTemplate = new THREE.Mesh(trailGeo, trailMat);

    const effect = {
      type: 'attack_beam',
      mesh: beamMesh,
      trail: trailTemplate,
      start: new THREE.Vector3(-7.5, 0, 0),
      control: new THREE.Vector3(-3.5, 3.8, 0), // Arching curve
      end: new THREE.Vector3(0, 0, 0),
      progress: 0,
      speed: 0.038,
      isBlocked,
      attackType,
    };

    activeEffectsRef.current.push(effect);

    // Blue Agent reacts: fire cyan defense beam from Blue to Target
    fireDefenseBeam();
  };

  // Fire cyan defense stream from Blue Agent to Target
  const fireDefenseBeam = () => {
    const scene = sceneRef.current;
    if (!scene) return;

    const curve = new THREE.LineCurve3(new THREE.Vector3(7.5, 0, 0), new THREE.Vector3(0, 0, 0));
    const tubeGeo = new THREE.TubeGeometry(curve, 20, 0.09, 8, false);
    const tubeMat = new THREE.MeshBasicMaterial({
      color: 0x06b6d4,
      transparent: true,
      opacity: 0.85,
    });
    const tubeMesh = new THREE.Mesh(tubeGeo, tubeMat);
    scene.add(tubeMesh);

    activeEffectsRef.current.push({
      type: 'defense_beam',
      mesh: tubeMesh,
      progress: 0,
      speed: 0.045,
    });
  };

  // Impact on Target: Flare shield if blocked, explosion if breached
  const triggerImpactEffect = (isBlocked, attackType) => {
    const scene = sceneRef.current;
    if (!scene) return;

    const shield = shieldMeshRef.current;
    const outerShield = shieldOuterMeshRef.current;

    if (isBlocked) {
      // Emerald / Cyan Deflection Shield
      if (shield) {
        shield.material.color.setHex(0x10b981);
        shield.material.emissive.setHex(0x10b981);
        shield.material.opacity = 0.8;
        shield.scale.set(1.25, 1.25, 1.25);
      }
      if (outerShield) {
        outerShield.material.color.setHex(0x10b981);
        outerShield.material.opacity = 0.4;
      }

      setTimeout(() => {
        if (shieldMeshRef.current) {
          shieldMeshRef.current.material.color.setHex(0x06b6d4);
          shieldMeshRef.current.material.emissive.setHex(0x06b6d4);
          shieldMeshRef.current.material.opacity = 0.15;
          shieldMeshRef.current.scale.set(1, 1, 1);
        }
        if (shieldOuterMeshRef.current) {
          shieldOuterMeshRef.current.material.color.setHex(0x06b6d4);
          shieldOuterMeshRef.current.material.opacity = 0.08;
        }
      }, 700);

      setFloatingCombatText({
        text: `🛡️ DEFLECTED: ${attackType} [403 FORBIDDEN]`,
        color: 'var(--green-primary)',
        badge: 'SHIELD BARRIER ACTIVE',
      });
    } else {
      // Red Breach Flare
      if (shield) {
        shield.material.color.setHex(0xf43f5e);
        shield.material.emissive.setHex(0xf43f5e);
        shield.material.opacity = 0.7;
      }
      if (outerShield) {
        outerShield.material.color.setHex(0xf43f5e);
        outerShield.material.opacity = 0.35;
      }

      setTimeout(() => {
        if (shieldMeshRef.current) {
          shieldMeshRef.current.material.color.setHex(0x06b6d4);
          shieldMeshRef.current.material.emissive.setHex(0x06b6d4);
          shieldMeshRef.current.material.opacity = 0.15;
        }
        if (shieldOuterMeshRef.current) {
          shieldOuterMeshRef.current.material.color.setHex(0x06b6d4);
          shieldOuterMeshRef.current.material.opacity = 0.08;
        }
      }, 550);

      setFloatingCombatText({
        text: `💥 BREACH DETECTED: ${attackType}`,
        color: 'var(--red-primary)',
        badge: 'PAYLOAD DELIVERED',
      });
    }

    setTimeout(() => setFloatingCombatText(null), 2500);

    // Impact Sparks
    const count = 40;
    const sparkGeo = new THREE.BufferGeometry();
    const sparkPos = new Float32Array(count * 3);
    const velocities = [];

    for (let i = 0; i < count; i++) {
      sparkPos[i * 3] = 0;
      sparkPos[i * 3 + 1] = 0;
      sparkPos[i * 3 + 2] = 0;
      velocities.push({
        x: (Math.random() - 0.5) * 0.28,
        y: (Math.random() - 0.5) * 0.28 + 0.06,
        z: (Math.random() - 0.5) * 0.28,
      });
    }

    sparkGeo.setAttribute('position', new THREE.BufferAttribute(sparkPos, 3));
    const sparkMat = new THREE.PointsMaterial({
      color: isBlocked ? 0x10b981 : 0xf43f5e,
      size: 0.16,
      transparent: true,
      opacity: 0.95,
      blending: THREE.AdditiveBlending,
    });
    const sparks = new THREE.Points(sparkGeo, sparkMat);
    scene.add(sparks);

    activeEffectsRef.current.push({
      type: 'explosion',
      mesh: sparks,
      velocities,
      progress: 0,
      speed: 0.045,
    });
  };

  // -------------------------------------------------------------
  // MOUSE DRAG ORBIT CONTROLS
  // -------------------------------------------------------------
  const handleMouseDown = (e) => {
    isDraggingRef.current = true;
    previousMousePosRef.current = { x: e.clientX, y: e.clientY };
  };

  const handleMouseMove = (e) => {
    if (!isDraggingRef.current || !cameraRef.current) return;
    const deltaX = e.clientX - previousMousePosRef.current.x;
    const deltaY = e.clientY - previousMousePosRef.current.y;

    cameraAngleRef.current.theta -= deltaX * 0.008;
    cameraAngleRef.current.phi = Math.max(0.1, Math.min(Math.PI / 2 - 0.05, cameraAngleRef.current.phi - deltaY * 0.008));

    const { theta, phi, radius } = cameraAngleRef.current;
    cameraRef.current.position.x = radius * Math.sin(phi) * Math.sin(theta);
    cameraRef.current.position.y = radius * Math.cos(phi);
    cameraRef.current.position.z = radius * Math.sin(phi) * Math.cos(theta);
    cameraRef.current.lookAt(0, 0, 0);

    previousMousePosRef.current = { x: e.clientX, y: e.clientY };
  };

  const handleMouseUp = () => {
    isDraggingRef.current = false;
  };

  const setCameraPreset = (mode) => {
    setViewMode(mode);
    if (!cameraRef.current) return;

    if (mode === 'front') {
      cameraAngleRef.current = { theta: 0, phi: Math.PI / 2.3, radius: 17 };
      cameraRef.current.position.set(0, 3, 17);
      cameraRef.current.lookAt(0, 0, 0);
    } else if (mode === 'overhead') {
      cameraAngleRef.current = { theta: 0, phi: 0.25, radius: 22 };
      cameraRef.current.position.set(0, 21, 5);
      cameraRef.current.lookAt(0, 0, 0);
    } else if (mode === 'red_eye') {
      cameraAngleRef.current = { theta: -Math.PI / 2.4, phi: Math.PI / 2.6, radius: 14 };
      cameraRef.current.position.set(-11, 2, 4);
      cameraRef.current.lookAt(0, 0, 0);
    } else if (mode === 'blue_eye') {
      cameraAngleRef.current = { theta: Math.PI / 2.4, phi: Math.PI / 2.6, radius: 14 };
      cameraRef.current.position.set(11, 2, 4);
      cameraRef.current.lookAt(0, 0, 0);
    } else {
      cameraAngleRef.current = { theta: 0, phi: Math.PI / 6, radius: 18 };
    }
  };

  return (
    <div style={{ position: 'relative', width: '100%', borderRadius: '12px', overflow: 'hidden', marginBottom: '16px' }}>
      {/* 3D WebGL Canvas Container */}
      <div
        ref={mountRef}
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        onMouseLeave={handleMouseUp}
        style={{
          width: '100%',
          height: '380px',
          background: 'linear-gradient(180deg, #05070d 0%, #0a0e17 100%)',
          cursor: isDraggingRef.current ? 'grabbing' : 'grab',
          border: '1px solid rgba(255, 255, 255, 0.08)',
          borderRadius: '12px',
          boxShadow: 'inset 0 0 50px rgba(0,0,0,0.8)',
        }}
      />

      {/* Floating 3D Node Labels */}
      <div style={{ position: 'absolute', top: '16px', left: '20px', pointerEvents: 'none' }}>
        <span className="badge badge-red" style={{ fontSize: '0.74rem', padding: '4px 10px', boxShadow: '0 0 15px rgba(244, 63, 94, 0.3)' }}>
          🔴 RED AGENT // MITRE Adversary
        </span>
      </div>

      <div style={{ position: 'absolute', top: '16px', left: '50%', transform: 'translateX(-50%)', pointerEvents: 'none' }}>
        <span className="badge badge-amber" style={{ fontSize: '0.74rem', padding: '4px 12px', boxShadow: '0 0 15px rgba(245, 158, 11, 0.3)' }}>
          🟡 TARGET CONTAINER // Gateway Proxy :8080
        </span>
      </div>

      <div style={{ position: 'absolute', top: '16px', right: '20px', pointerEvents: 'none' }}>
        <span className="badge badge-blue" style={{ fontSize: '0.74rem', padding: '4px 10px', boxShadow: '0 0 15px rgba(6, 182, 212, 0.3)' }}>
          🔵 BLUE AGENT // AI Guardian
        </span>
      </div>

      {/* Floating Combat Toast Notification */}
      {floatingCombatText && (
        <div style={{
          position: 'absolute',
          top: '52px',
          left: '50%',
          transform: 'translateX(-50%)',
          background: 'rgba(8, 12, 20, 0.95)',
          border: `1.5px solid ${floatingCombatText.color}`,
          boxShadow: `0 0 30px ${floatingCombatText.color}66`,
          color: floatingCombatText.color,
          padding: '8px 20px',
          borderRadius: '24px',
          fontSize: '0.86rem',
          fontWeight: 800,
          fontFamily: 'var(--font-heading)',
          letterSpacing: '0.04em',
          pointerEvents: 'none',
          animation: 'fadeSlideDown 0.3s ease forwards',
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          backdropFilter: 'blur(10px)',
        }}>
          <span>{floatingCombatText.text}</span>
          <span style={{
            fontSize: '0.65rem',
            padding: '2px 6px',
            borderRadius: '4px',
            background: 'rgba(255,255,255,0.1)',
            color: '#ffffff',
          }}>
            {floatingCombatText.badge}
          </span>
        </div>
      )}

      {/* Camera View Controls (Bottom Right of Canvas) */}
      <div style={{
        position: 'absolute',
        bottom: '12px',
        right: '14px',
        display: 'flex',
        gap: '6px',
        background: 'rgba(10, 14, 22, 0.88)',
        padding: '4px 8px',
        borderRadius: '8px',
        border: '1px solid rgba(255, 255, 255, 0.1)',
        backdropFilter: 'blur(10px)',
      }}>
        <button
          className={viewMode === 'cinematic' ? 'btn-primary' : 'btn-secondary'}
          style={{ fontSize: '0.68rem', padding: '3px 8px' }}
          onClick={() => setCameraPreset('cinematic')}
          title="Auto-rotating cinematic orbit view"
        >
          <RotateCw size={11} style={{ marginRight: '4px' }} />
          Orbit
        </button>
        <button
          className={viewMode === 'front' ? 'btn-primary' : 'btn-secondary'}
          style={{ fontSize: '0.68rem', padding: '3px 8px' }}
          onClick={() => setCameraPreset('front')}
          title="Front tactical view"
        >
          <Eye size={11} style={{ marginRight: '4px' }} />
          Front
        </button>
        <button
          className={viewMode === 'overhead' ? 'btn-primary' : 'btn-secondary'}
          style={{ fontSize: '0.68rem', padding: '3px 8px' }}
          onClick={() => setCameraPreset('overhead')}
          title="Overhead tactical view"
        >
          <Camera size={11} style={{ marginRight: '4px' }} />
          Top-Down
        </button>
        <button
          className={viewMode === 'red_eye' ? 'btn-primary' : 'btn-secondary'}
          style={{ fontSize: '0.68rem', padding: '3px 8px', color: viewMode === 'red_eye' ? '#ffffff' : '#fda4af' }}
          onClick={() => setCameraPreset('red_eye')}
          title="Adversary Red Point of View"
        >
          <Crosshair size={11} style={{ marginRight: '4px' }} />
          Red Eye
        </button>
        <button
          className={viewMode === 'blue_eye' ? 'btn-primary' : 'btn-secondary'}
          style={{ fontSize: '0.68rem', padding: '3px 8px', color: viewMode === 'blue_eye' ? '#ffffff' : '#7dd3fc' }}
          onClick={() => setCameraPreset('blue_eye')}
          title="Guardian Blue Point of View"
        >
          <Shield size={11} style={{ marginRight: '4px' }} />
          Guardian Eye
        </button>
      </div>

      {/* Drag Hint (Bottom Left of Canvas) */}
      <div style={{
        position: 'absolute',
        bottom: '12px',
        left: '14px',
        fontSize: '0.68rem',
        color: 'var(--text-dim)',
        background: 'rgba(10, 14, 22, 0.75)',
        padding: '3px 10px',
        borderRadius: '6px',
        border: '1px solid rgba(255,255,255,0.05)',
        pointerEvents: 'none',
        display: 'flex',
        alignItems: 'center',
        gap: '6px',
      }}>
        <span>🖱️ Drag to rotate</span>
        <span style={{ color: 'var(--border-subtle)' }}>|</span>
        <span>Scroll to zoom</span>
      </div>

      <style>{`
        @keyframes fadeSlideDown {
          from { opacity: 0; transform: translate(-50%, -12px); }
          to { opacity: 1; transform: translate(-50%, 0); }
        }
      `}</style>
    </div>
  );
}
