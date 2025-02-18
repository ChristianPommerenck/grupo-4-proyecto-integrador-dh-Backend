package com.flavioramses.huellitasbackend.controller;

import com.flavioramses.huellitasbackend.Exception.BadRequestException;
import com.flavioramses.huellitasbackend.Exception.ResourceNotFoundException;
import com.flavioramses.huellitasbackend.model.Alojamiento;
import com.flavioramses.huellitasbackend.service.AlojamientoService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;


import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping(path = "/alojamientos")
public class AlojamientoController {

    @Autowired
    public AlojamientoService alojamientoService;

    @PostMapping("/saveAlojamiento")
    public ResponseEntity<Alojamiento> saveAlojamiento(@RequestBody Alojamiento alojamiento) throws BadRequestException {
        /*Alojamiento alojamientoGuardado = alojamientoService.saveAlojamiento(alojamiento);
        Optional<Alojamiento> alojamientoById = alojamientoService.getAlojamientoById(alojamiento.getId());
        if(alojamientoById.isPresent()){
            return ResponseEntity.ok(alojamientoGuardado);
        }else{
            throw new BadRequestException("Hubo un error al registrar el alojamiento");
        }*/


        return ResponseEntity.status(200).body(alojamientoService.saveAlojamiento(alojamiento));
    }

    @GetMapping("/listartodos")
    public ResponseEntity<List<Alojamiento>> getAllAlojamientos() {
        return ResponseEntity.status(200).body(alojamientoService.getAllAlojamientos());
    }

    @GetMapping("buscar/{Id}")
    public ResponseEntity<Optional<Alojamiento>> getAlojamientoById(@PathVariable Long alojamientoId) throws ResourceNotFoundException {
        Optional<Alojamiento> alojamientoBuscado = alojamientoService.getAlojamientoById(alojamientoId);
        if(alojamientoBuscado.isPresent()){
            return ResponseEntity.ok(alojamientoBuscado);
        }else{
            throw new ResourceNotFoundException("Alojamiento no encontrado");
        }

    }

    @PutMapping
    public ResponseEntity<Alojamiento> updateAlojamiento(@RequestBody Alojamiento alojamiento) throws BadRequestException {
          try{
              return ResponseEntity.ok(alojamientoService.updateAlojamiento(alojamiento));
          }catch (Exception e){
              throw new BadRequestException("Ocurrio un error al actualizar el alojamiento");
          }
    }

    @DeleteMapping("/eliminar/{Id}")
    public ResponseEntity<Void> deleteAlojamientoById(@PathVariable("Id") Long alojamientoId) {
        alojamientoService.deleteAlojamientoById(alojamientoId);
        return ResponseEntity.status(204).build();
    }
}
