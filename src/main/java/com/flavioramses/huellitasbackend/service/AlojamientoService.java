package com.flavioramses.huellitasbackend.service;

import com.flavioramses.huellitasbackend.model.Alojamiento;
import com.flavioramses.huellitasbackend.repository.AlojamientoRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class AlojamientoService {

    @Autowired
    public AlojamientoRepository alojamientoRepository;

    public Alojamiento saveAlojamiento(Alojamiento alojamiento) {
        return alojamientoRepository.save(alojamiento);
    }

    public List<Alojamiento> getAllAlojamientos() {
        return alojamientoRepository.findAll();
    }

    public Alojamiento updateAlojamiento(Alojamiento alojamiento) {
        return alojamientoRepository.save(alojamiento);
    }

    public Optional<Alojamiento> getAlojamientoById (Long id) {
        return alojamientoRepository.findById(id);
    }

    public void deleteAlojamientoById(Long id) {
        alojamientoRepository.deleteById(id);
    }
}
