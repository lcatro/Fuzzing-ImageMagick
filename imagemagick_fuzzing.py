
import os
import random
import time

from imagemagick_write_fuzzing import *


def build_image_header_flag() :
    image_header_flag = []

    image_header_flag.append(('WEBP', 8, 'WEBP'))
    image_header_flag.append(('AVI', 0, 'RIFF'))
    image_header_flag.append(('8BIMWTEXT', 0, '8\000B\000I\000M\000#'))
    image_header_flag.append(('8BIMTEXT', 0, '8BIM#'))
    image_header_flag.append(('8BIM', 0, '8BIM'))
    image_header_flag.append(('BMP', 0, 'BA'))
    image_header_flag.append(('BMP', 0, 'BM'))
    image_header_flag.append(('BMP', 0, 'CI'))
    image_header_flag.append(('BMP', 0, 'CP'))
    image_header_flag.append(('BMP', 0, 'IC'))
    image_header_flag.append(('BMP', 0, 'PI'))
    image_header_flag.append(('CALS', 21, 'version: MIL-STD-1840'))
    image_header_flag.append(('CALS', 0, 'srcdocid:'))
    image_header_flag.append(('CALS', 9, 'srcdocid:'))
    image_header_flag.append(('CALS', 8, 'rorient:'))
    image_header_flag.append(('CGM', 0, 'BEGMF'))
    image_header_flag.append(('CIN', 0, '\200\052\137\327'))
    image_header_flag.append(('DCM', 128, 'DICM'))
    image_header_flag.append(('DCX', 0, '\261\150\336\72'))
    image_header_flag.append(('DIB', 0, '\050\000'))
    image_header_flag.append(('DOT', 0, 'digraph'))
    image_header_flag.append(('DPX', 0, 'SDPX'))
    image_header_flag.append(('DPX', 0, 'XPDS'))
    image_header_flag.append(('EMF', 40, '\040\105\115\106\000\000\001\000'))
    image_header_flag.append(('EPT', 0, '\305\320\323\306'))
    image_header_flag.append(('FAX', 0, 'DFAX'))
    image_header_flag.append(('FIG', 0, '#FIG'))
    image_header_flag.append(('FITS', 0, 'IT0'))
    image_header_flag.append(('FITS', 0, 'SIMPLE'))
    image_header_flag.append(('FPX', 0, '\320\317\021\340'))
    image_header_flag.append(('GIF', 0, 'GIF8'))
    image_header_flag.append(('HDF', 1, 'HDF'))
    image_header_flag.append(('HPGL', 0, 'IN;'))
    image_header_flag.append(('HPGL', 0, '\033E\033'))
    image_header_flag.append(('HTML', 1, 'HTML'))
    image_header_flag.append(('HTML', 1, 'html'))
    image_header_flag.append(('ILBM', 8, 'ILBM'))
    image_header_flag.append(('IPTCWTEXT', 0, '\062\000#\000\060\000=\000\042\000&\000#\000\060\000;\000&\000#\000\062\000;\000\042\000'))
    image_header_flag.append(('IPTCTEXT', 0, '2#0=\042&#0;&#2;\042'))
    image_header_flag.append(('IPTC', 0, '\034\002'))
    image_header_flag.append(('JNG', 0, '\213JNG\r\n\032\n'))
    image_header_flag.append(('JPEG', 0, '\377\330\377'))
    image_header_flag.append(('JPC', 0, '\377\117'))
    image_header_flag.append(('JP2', 4, '\152\120\040\040\015'))
    image_header_flag.append(('MAT', 0, 'MATLAB 5.0 MAT-file,'))
    image_header_flag.append(('MIFF', 0, 'Id=ImageMagick'))
    image_header_flag.append(('MIFF', 0, 'id=ImageMagick'))
    image_header_flag.append(('MNG', 0, '\212MNG\r\n\032\n'))
    image_header_flag.append(('MPC', 0, 'id=MagickCache'))
    image_header_flag.append(('MPEG', 0, '\000\000\001\263'))
    image_header_flag.append(('PCD', 2048, 'PCD_'))
    image_header_flag.append(('PCL', 0, '\033E\033'))
    image_header_flag.append(('PCX', 0, '\012\002'))
    image_header_flag.append(('PCX', 0, '\012\005'))
    image_header_flag.append(('PDB', 60, 'vIMGView'))
    image_header_flag.append(('PDF', 0, '%PDF-'))
    image_header_flag.append(('PFA', 0, '%!PS-AdobeFont-1.0'))
    image_header_flag.append(('PFB', 6, '%!PS-AdobeFont-1.0'))
    image_header_flag.append(('PGX', 0, 'PG ML'))
    image_header_flag.append(('PGX', 0, 'PG LM'))
    image_header_flag.append(('PICT', 522, '\000\021\002\377\014\000'))
    image_header_flag.append(('PNG', 0, '\211PNG\r\n\032\n'))
    image_header_flag.append(('PBM', 0, 'P1'))
    image_header_flag.append(('PGM', 0, 'P2'))
    image_header_flag.append(('PPM', 0, 'P3'))
    image_header_flag.append(('PBM', 0, 'P4'))
    image_header_flag.append(('PGM', 0, 'P5'))
    image_header_flag.append(('PPM', 0, 'P6'))
    image_header_flag.append(('P7', 0, 'P7 332'))
    image_header_flag.append(('PAM', 0, 'P7'))
    image_header_flag.append(('PS', 0, '%!'))
    image_header_flag.append(('PS', 0, '\004%!'))
    image_header_flag.append(('PS', 0, '\305\320\323\306'))
    image_header_flag.append(('PSD', 0, '8BPS'))
    image_header_flag.append(('PWP', 0, 'SFW95'))
    image_header_flag.append(('RAD', 0, '#?RADIANCE'))
    image_header_flag.append(('RAD', 0, 'VIEW= '))
    image_header_flag.append(('RLE', 0, '\122\314'))
    image_header_flag.append(('SCT', 0, 'CT'))
    image_header_flag.append(('SFW', 0, 'SFW94'))
    image_header_flag.append(('SGI', 0, '\001\332'))
    image_header_flag.append(('SUN', 0, '\131\246\152\225'))
    image_header_flag.append(('SVG', 1, '?XML'))
    image_header_flag.append(('SVG', 1, '?xml'))
    image_header_flag.append(('TIFF', 0, '\115\115\000\052'))
    image_header_flag.append(('TIFF', 0, '\111\111\052\000'))
    image_header_flag.append(('BIGTIFF', 0, '\115\115\000\053\000\010\000\000'))
    image_header_flag.append(('BIGTIFF', 0, '\111\111\053\000\010\000\000\000'))
    image_header_flag.append(('VICAR', 0, 'LBLSIZE'))
    image_header_flag.append(('VICAR', 0, 'NJPL1I'))
    image_header_flag.append(('VIFF', 0, '\253\001'))
    image_header_flag.append(('WMF', 0, '\327\315\306\232'))
    image_header_flag.append(('WMF', 0, '\001\000\011\000'))
    image_header_flag.append(('WPG', 0, '\377WPC'))
    image_header_flag.append(('XBM', 0, '#define'))
    image_header_flag.append(('XCF', 0, 'gimp xcf'))
    image_header_flag.append(('XPM', 1, '* XPM *'))
    image_header_flag.append(('XWD', 4, '\007\000\000'))
    image_header_flag.append(('XWD', 5, '\000\000\007'))
    
    return image_header_flag

def build_random_data(data_length) :
    data = b''
    
    for data_index in range(data_length) :
        data += chr(random.randrange(255))
        
    return data

def build_random_image(data_length) :
    random_image_header = random.choice(image_header)
        
    return build_random_data(random_image_header[1]) + random_image_header[2] + build_random_data(data_length)

def write_file(file_path,data) :
    file = open(file_path,'w')
    
    if file :
        file.write(data)
    
    file.close()
    
    
image_header = build_image_header_flag()


if __name__ == '__main__' :
    max_fuzzing_image_length = 2048
    fuzzing_dir = 'graphicsmagick_fuzzing'
    fuzzing_index = 0
    crash_index   = 0
    
    if not os.path.exists(fuzzing_dir) :
        os.mkdir(fuzzing_dir)
    
    while True :
        random_image = build_random_image(max_fuzzing_image_length)
        
        write_file('fuzzing_genarate_image',random_image)
        
        for graphicsmagick_output_format_index in imagemagick_output_format :
            result = run_graphicsmagick_convert('fuzzing_genarate_image',fuzzing_dir + '/' +graphicsmagick_output_format_index)
            
            if result[0] :
                graphicsmagick_output_extern_name = get_extern_name(graphicsmagick_output_format_index)
                crash_file_path = ''

                if not None == result[1] :
                    if 'SEGV' == result[1] or 'Memory-Leak' == result[1] :
                        if check_exist_crash(fuzzing_dir,result[1],result[2]) :
                            continue

                        crash_file_path = result[1] + '-' + result[2] + '_output_' + graphicsmagick_output_extern_name +'_' + str(time.time())
                    else :  #  crash overflow ..
                        if check_exist_crash(fuzzing_dir,result[1],result[2] + '-' + result[3]) :
                            continue

                        crash_file_path = result[1] + '-' + result[2] + '-' + result[3] + '_output_' + graphicsmagick_output_extern_name +'_' + str(time.time())

                    print_output('Crash (' + str(time.time()) + ') ' + result[1] + ' ' + result[2] + ' ' + graphicsmagick_output_extern_name)
                else :
                    crash_file_path = 'unknow_crash_output_' + graphicsmagick_output_extern_name + '_' + str(time.time())

                    print_output('Crash (' + str(time.time()) + ') unknow crash')
                    
                os.system('cp fuzzing_genarate_image ' + fuzzing_dir + '/' + crash_file_path)
                
                crash_index += 1
                
            fuzzing_index += 1
                
            print_progress(0,str(crash_index) + '/' + str(fuzzing_index))
    
    
    
    
    
