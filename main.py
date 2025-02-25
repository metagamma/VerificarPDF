import os
import sys
import time
import multiprocessing as mp
import logging
from concurrent.futures import ProcessPoolExecutor, as_completed
from typing import Dict, List, Tuple, Optional, Union

# Bibliotecas para manipulación de PDF
import pikepdf
import PyPDF2
from PyPDF2.errors import PdfReadError
from PyPDF2 import PdfReader
import hashlib

# Para la verificación de firmas digitales y sellos de tiempo
from endesive import pdf as endesive_pdf
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from asn1crypto import cms, tsp

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

class PDFVerifier:
    """Clase para verificar la integridad de archivos PDF."""
    
    def __init__(self, num_workers: Optional[int] = None):
        """
        Inicializa el verificador de PDF.
        
        Args:
            num_workers: Número de procesos a utilizar. Si es None, usará el máximo disponible.
        """
        self.num_workers = num_workers or mp.cpu_count()
        logger.info(f"Utilizando {self.num_workers} procesos para la verificación")
    
    def verify_file(self, filepath: str, check_signature: bool = False, 
                   check_timestamp: bool = False) -> Dict:
        """
        Verifica un archivo PDF.
        
        Args:
            filepath: Ruta al archivo PDF.
            check_signature: Si se debe verificar la firma digital.
            check_timestamp: Si se debe verificar el sello de tiempo.
            
        Returns:
            Diccionario con los resultados de verificación.
        """
        start_time = time.time()
        
        if not os.path.exists(filepath):
            return {"status": "error", "message": f"Archivo no encontrado: {filepath}"}
        
        filesize_mb = os.path.getsize(filepath) / (1024 * 1024)
        logger.info(f"Verificando archivo {filepath} ({filesize_mb:.2f} MB)")
        
        try:
            # Verificación básica de estructura PDF
            structure_check = self._verify_pdf_structure(filepath)
            if not structure_check["valid"]:
                return {
                    "status": "error", 
                    "message": f"Estructura PDF inválida: {structure_check['message']}",
                    "execution_time": time.time() - start_time
                }
            
            # Verificación página por página
            page_results = self._verify_pages(filepath)
            
            # Verificación de firma digital y sello de tiempo (si se solicita)
            signature_results = None
            timestamp_results = None
            
            if check_signature:
                signature_results = self._verify_signature(filepath)
            
            if check_timestamp:
                timestamp_results = self._verify_timestamp(filepath)
            
            execution_time = time.time() - start_time
            
            return {
                "status": "success",
                "filepath": filepath,
                "filesize_mb": filesize_mb,
                "structure_check": structure_check,
                "page_results": page_results,
                "signature_results": signature_results,
                "timestamp_results": timestamp_results,
                "execution_time": execution_time
            }
        
        except Exception as e:
            logger.error(f"Error verificando archivo {filepath}: {str(e)}")
            return {
                "status": "error",
                "message": f"Error al verificar: {str(e)}",
                "execution_time": time.time() - start_time
            }
    
    def _verify_pdf_structure(self, filepath: str) -> Dict:
        """Verifica la estructura básica del PDF."""
        try:
            # Intentamos abrir el PDF con pikepdf, que es rápido y estricto
            with pikepdf.Pdf.open(filepath, allow_overwriting_input=False) as pdf:
                num_pages = len(pdf.pages)
            
            return {"valid": True, "num_pages": num_pages}
        
        except Exception as e:
            return {"valid": False, "message": str(e)}
    
    def _verify_pages(self, filepath: str) -> Dict:
        """Verifica cada página del PDF usando paralelización."""
        try:
            # Primero obtenemos la cantidad de páginas con PyPDF2
            with open(filepath, 'rb') as f:
                reader = PdfReader(f)
                total_pages = len(reader.pages)
            
            # Dividimos las páginas en chunks para procesamiento paralelo
            page_ranges = self._split_workload(total_pages)
            
            # Verificamos las páginas en paralelo
            with ProcessPoolExecutor(max_workers=self.num_workers) as executor:
                futures = [
                    executor.submit(self._verify_page_range, filepath, start_page, end_page)
                    for start_page, end_page in page_ranges
                ]
                
                results = []
                for future in as_completed(futures):
                    results.extend(future.result())
            
            # Procesamos los resultados
            damaged_pages = [r["page"] for r in results if not r["valid"]]
            
            return {
                "total_pages": total_pages,
                "verified_pages": len(results),
                "damaged_pages": damaged_pages,
                "all_pages_valid": len(damaged_pages) == 0
            }
            
        except Exception as e:
            logger.error(f"Error en verificación por páginas: {str(e)}")
            return {
                "error": str(e),
                "total_pages": 0,
                "verified_pages": 0,
                "damaged_pages": [],
                "all_pages_valid": False
            }
    
    def _verify_page_range(self, filepath: str, start_page: int, end_page: int) -> List[Dict]:
        """Verifica un rango de páginas específico."""
        results = []
        
        try:
            with pikepdf.Pdf.open(filepath) as pdf:
                for page_num in range(start_page, end_page + 1):
                    if page_num >= len(pdf.pages):
                        break
                    
                    try:
                        # Intentamos acceder al contenido de la página
                        page = pdf.pages[page_num]
                        # Verificamos que tenga contenido válido
                        if "/Contents" in page:
                            if isinstance(page["/Contents"], pikepdf.Array):
                                for obj in page["/Contents"]:
                                    _ = obj.read_bytes()
                            else:
                                _ = page["/Contents"].read_bytes()
                        
                        results.append({"page": page_num, "valid": True})
                    except Exception as e:
                        results.append({"page": page_num, "valid": False, "error": str(e)})
        
        except Exception as e:
            # Si hay un error al abrir el archivo, marcamos todas las páginas como dañadas
            for page_num in range(start_page, end_page + 1):
                results.append({"page": page_num, "valid": False, "error": str(e)})
        
        return results
    
    def _split_workload(self, total_pages: int) -> List[Tuple[int, int]]:
        """Divide el trabajo en ranges para procesamiento paralelo."""
        chunk_size = max(1, total_pages // self.num_workers)
        ranges = []
        
        for i in range(0, total_pages, chunk_size):
            end = min(i + chunk_size - 1, total_pages - 1)
            ranges.append((i, end))
        
        return ranges
    
    def _verify_signature(self, filepath: str) -> Dict:
        """Verifica la firma digital del PDF."""
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
            
            # Usamos endesive para verificar las firmas
            signatures = endesive_pdf.verify(data)
            
            if not signatures:
                return {"signed": False, "message": "El documento no está firmado"}
            
            results = []
            for i, signature in enumerate(signatures):
                if signature.get('hashok') and signature.get('signatureok'):
                    cert_data = signature.get('cert')
                    if cert_data:
                        cert = x509.load_der_x509_certificate(cert_data, default_backend())
                        subject = cert.subject.rfc4514_string()
                        issuer = cert.issuer.rfc4514_string()
                    else:
                        subject = "Desconocido"
                        issuer = "Desconocido"
                    
                    results.append({
                        "signature_index": i,
                        "valid": True,
                        "subject": subject,
                        "issuer": issuer,
                        "sign_date": signature.get('signdate', "Desconocido")
                    })
                else:
                    results.append({
                        "signature_index": i,
                        "valid": False,
                        "hash_valid": signature.get('hashok', False),
                        "signature_valid": signature.get('signatureok', False)
                    })
            
            return {
                "signed": True,
                "signatures_count": len(signatures),
                "all_valid": all(r["valid"] for r in results),
                "signatures": results
            }
        
        except Exception as e:
            logger.error(f"Error al verificar firma: {str(e)}")
            return {"signed": False, "error": str(e)}
    
    def _verify_timestamp(self, filepath: str) -> Dict:
        """Verifica el sello de tiempo del PDF."""
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
            
            # Verificamos si hay firmas con sello de tiempo
            signatures = endesive_pdf.verify(data)
            
            if not signatures:
                return {"timestamped": False, "message": "El documento no tiene sellos de tiempo"}
            
            results = []
            for i, signature in enumerate(signatures):
                cms_data = signature.get('cms')
                if not cms_data:
                    continue
                
                try:
                    # Extraemos y verificamos el sello de tiempo
                    signed_data = cms.ContentInfo.load(cms_data).content
                    ts_info = None
                    
                    for attr in signed_data['signer_infos'][0]['signed_attrs']:
                        if attr['type'].native == 'signing-time':
                            signing_time = attr['values'][0].native
                            ts_info = {"time": signing_time}
                        elif attr['type'].native == 'signature-time-stamp-token':
                            ts_token = tsp.TimeStampToken.load(attr['values'][0].native)
                            ts_info = {
                                "policy": ts_token['tst_info']['policy'].native,
                                "serial": ts_token['tst_info']['serial_number'].native,
                                "time": ts_token['tst_info']['gen_time'].native,
                                "tsa": ts_token['tst_info']['tsa'].native if 'tsa' in ts_token['tst_info'] else None
                            }
                    
                    if ts_info:
                        results.append({
                            "signature_index": i,
                            "has_timestamp": True,
                            "timestamp_info": ts_info
                        })
                    else:
                        results.append({
                            "signature_index": i,
                            "has_timestamp": False
                        })
                
                except Exception as e:
                    results.append({
                        "signature_index": i,
                        "has_timestamp": False,
                        "error": str(e)
                    })
            
            return {
                "timestamped": any(r["has_timestamp"] for r in results),
                "timestamp_count": sum(1 for r in results if r["has_timestamp"]),
                "details": results
            }
        
        except Exception as e:
            logger.error(f"Error al verificar sello de tiempo: {str(e)}")
            return {"timestamped": False, "error": str(e)}
    
    def batch_verify(self, filepaths: List[str], check_signature: bool = False,
                    check_timestamp: bool = False) -> Dict:
        """
        Verifica múltiples archivos PDF en paralelo.
        
        Args:
            filepaths: Lista de rutas a archivos PDF.
            check_signature: Si se debe verificar firmas digitales.
            check_timestamp: Si se debe verificar sellos de tiempo.
            
        Returns:
            Diccionario con resultados por archivo.
        """
        start_time = time.time()
        
        # Verificamos los archivos en paralelo
        with ProcessPoolExecutor(max_workers=self.num_workers) as executor:
            futures = [
                executor.submit(self.verify_file, filepath, check_signature, check_timestamp)
                for filepath in filepaths
            ]
            
            results = {}
            for future, filepath in zip(as_completed(futures), filepaths):
                results[filepath] = future.result()
        
        # Resumen de resultados
        valid_files = [path for path, result in results.items() 
                      if result["status"] == "success" and 
                      result.get("page_results", {}).get("all_pages_valid", False)]
        
        invalid_files = [path for path, result in results.items() 
                        if result["status"] == "error" or 
                        not result.get("page_results", {}).get("all_pages_valid", False)]
        
        return {
            "execution_time": time.time() - start_time,
            "total_files": len(filepaths),
            "valid_files": len(valid_files),
            "invalid_files": len(invalid_files),
            "results": results
        }


def main():
    """Función principal para uso como script."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Verifica archivos PDF')
    parser.add_argument('files', nargs='+', help='Archivos PDF a verificar')
    parser.add_argument('--signature', action='store_true', help='Verificar firmas digitales')
    parser.add_argument('--timestamp', action='store_true', help='Verificar sellos de tiempo')
    parser.add_argument('--workers', type=int, default=None, 
                        help='Número de procesos a utilizar (default: núcleos disponibles)')
    
    args = parser.parse_args()
    
    verifier = PDFVerifier(num_workers=args.workers)
    
    if len(args.files) == 1:
        # Verificar un solo archivo
        result = verifier.verify_file(args.files[0], args.signature, args.timestamp)
        if result["status"] == "success":
            print(f"\nResultado para {args.files[0]}:")
            print(f"- Estado: {'Válido' if result['page_results']['all_pages_valid'] else 'Inválido'}")
            print(f"- Páginas: {result['page_results']['total_pages']}")
            if not result['page_results']['all_pages_valid']:
                print(f"- Páginas dañadas: {result['page_results']['damaged_pages']}")
            
            if args.signature and result.get("signature_results"):
                sig = result["signature_results"]
                print(f"\nFirma digital: {'Presente' if sig['signed'] else 'No presente'}")
                if sig['signed']:
                    print(f"- Firmas válidas: {sig['all_valid']}")
                    print(f"- Número de firmas: {sig['signatures_count']}")
            
            if args.timestamp and result.get("timestamp_results"):
                ts = result["timestamp_results"]
                print(f"\nSello de tiempo: {'Presente' if ts['timestamped'] else 'No presente'}")
                if ts['timestamped']:
                    print(f"- Número de sellos: {ts['timestamp_count']}")
            
            print(f"\nTiempo de ejecución: {result['execution_time']:.2f} segundos")
        else:
            print(f"\nError al verificar {args.files[0]}: {result['message']}")
    else:
        # Verificar múltiples archivos
        results = verifier.batch_verify(args.files, args.signature, args.timestamp)
        
        print(f"\nResumen de verificación:")
        print(f"- Archivos verificados: {results['total_files']}")
        print(f"- Archivos válidos: {results['valid_files']}")
        print(f"- Archivos inválidos: {results['invalid_files']}")
        print(f"- Tiempo total de ejecución: {results['execution_time']:.2f} segundos")
        
        # Mostrar los archivos inválidos
        if results['invalid_files']:
            print("\nArchivos con problemas:")
            for filepath in results['invalid_files']:
                result = results['results'][filepath]
                if result["status"] == "error":
                    print(f"- {filepath}: {result['message']}")
                else:
                    damaged_pages = result.get('page_results', {}).get('damaged_pages', [])
                    print(f"- {filepath}: {len(damaged_pages)} páginas dañadas {damaged_pages}")


if __name__ == "__main__":
    main()