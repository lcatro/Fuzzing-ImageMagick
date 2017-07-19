
import os
import subprocess
import sys
import threading
import time


MAX_OUTPUT_FILES_DISK_SPACE = 10 * 1024 * 1024 * 1024  #  10 GB disk space for collect GraphicsMagick output files ..
MAX_PROCESS_WAIT_TIME = 10  #  wait time for process exit ..


def run_graphicsmagick_convert(input_file,output_file) :
    process = subprocess.Popen(['./magick','convert',input_file,output_file],stdout = subprocess.PIPE,stderr = subprocess.PIPE)
    process_timeout_exit = lambda : process.kill()
    timeout = threading.Timer(MAX_PROCESS_WAIT_TIME,process_timeout_exit)
    
    timeout.start()
    process.wait()
    timeout.cancel()
    
    std_error_output = process.stderr.read()

    if len(std_error_output) and not -1 == std_error_output.find('========') :  #  ASAN Check ..
        flag_address_sanitize = 'ERROR: AddressSanitizer: '
        flag_address_sanitize_offset = std_error_output.find(flag_address_sanitize)
        flag_leak_sanitize = 'ERROR: LeakSanitizer: '
        flag_leak_sanitize_offset = std_error_output.find(flag_leak_sanitize)

        if not -1 == flag_address_sanitize_offset :
            crash_type = std_error_output[flag_address_sanitize_offset + len(flag_address_sanitize) : ]
            crash_type = crash_type[ : crash_type.find('on') ].strip()
            crash_type_detail = ''

            flag_at_pc = 'pc '
            flag_at_pc_offset = std_error_output.find(flag_at_pc)

            crash_point = std_error_output[flag_at_pc_offset + len(flag_at_pc) : ]
            crash_point = crash_point[ : crash_point.find(' bp')]

            if not -1 == crash_type.find('buffer-overflow') :  #  stack and heap
                flag_of_size = ' of size'
                flag_of_size_offset = std_error_output.find(flag_of_size)

                crash_type_detail = std_error_output[ : flag_of_size_offset]
                crash_type_detail = crash_type_detail[crash_type_detail.rfind('\n') : ].strip()
            elif 'SEGV' == crash_type :  #  Null point reference ..
                flag_of_address = 'unknown address'
                flag_of_address_offset = std_error_output.find(flag_of_address)

                crash_type_detail = std_error_output[flag_of_address_offset + len(flag_of_address) : ]
                crash_type_detail = crash_type_detail[ : crash_type_detail.find('(')].strip()

#            print crash_type,crash_type_detail,crash_point  #  print for debug ..

            return True,crash_type,crash_type_detail,crash_point,std_error_output
        elif not -1 == flag_leak_sanitize_offset :
            flag_direct_leak = 'Direct leak'
            flag_indirect_leak = 'Indirect leak'
            memory_leak_id = std_error_output.count(flag_direct_leak) + std_error_output.count(flag_indirect_leak)

            return True , 'Memory-Leak' , str(memory_leak_id) , None , std_error_output

#        print 'Other Crash ..'
#        print std_error_output

        return True , None , None , None , std_error_output

    return False , None , None , None , None

def delete_all_file(dir) :
    dir_list = os.listdir(dir)

    for dir_index in dir_list :
        os.remove(dir + '/' + dir_index)

def write_file(file_path,data) :
    file = open(file_path,'w')
    
    if file :
        file.write(data)
    
    file.close()
    
def read_file(file_path) :
    file = open(file_path,'r')
    file_data = None
    
    if file :
        file_data = file.read()
        
    file.close()
    
    return file_data
        
def copy_file(src_path,dest_path) :
    src_path_data = read_file(src_path)
    
    if not None == src_path_data :
        write_file(dest_path,src_path_data)
    
def copy_all_file(src_dir,dest_dir) :
    dir_list = os.listdir(src_dir)
    max_file_space = 0

    for dir_index in dir_list :
        file_path = src_dir + '/' + dir_index
        max_file_space += os.path.getsize(file_path)
        
        if max_file_space < MAX_OUTPUT_FILES_DISK_SPACE :
            copy_file(file_path,dest_dir + '/' + dir_index) #  os.system('cp ' + file_path + ' ' + dest_dir)
        else :
            break

def get_extern_name(file_path) :
    extern_name_split_offset = file_path.rfind('.')

    if not -1 == extern_name_split_offset :
        return file_path[extern_name_split_offset + 1: ]

    return ''

def check_exist_crash(crash_dir,crash_type,crash_information) :
    crash_file_list = os.listdir(crash_dir)
    
    if len(crash_file_list) :
        for crash_file_index in crash_file_list :
            if crash_file_index.startswith(crash_type + '-' + crash_information) :
                return True
        
    return False

def print_output(new_information) :
    print '\r' , new_information

def print_progress(progress_number,other_information) :
    print '\r' , 
    
    print_progress_block = int(progress_number * 100) / 10
    print_progress_block_string = ''
    
    for print_progress_block_index in range(print_progress_block) :
        print_progress_block_string += '#'
        
    for print_progress_block_index in range(10 - print_progress_block) :
        print_progress_block_string += '_'
    
    print_progress_block_string += ' (' + str(int(progress_number * 100)) + ') '
    
    sys.stdout.write(print_progress_block_string +  str(other_information) + '\r')
    sys.stdout.flush()
    
imagemagick_output_format = ['output.aai','output.art','output.avs','output.bgr','output.bmp','output.braille','output.cals','output.cin','output.cip','output.clipboard','output.cmyk','output.dds','output.debug','output.dib','output.dpx','output.ept','output.exr','output.fax','output.fits','output.flif','output.fpx','output.gif','output.gray','output.histogram','output.hrz','output.html','output.icon','output.info','output.inline','output.ipl','output.jbig','output.jp2','output.jpeg','output.json','output.magick','output.map','output.mask','output.mat','output.matte','output.meta','output.miff','output.mono','output.mpc','output.mpeg','output.mpr','output.msl','output.mtv','output.mvg','output.null','output.otb','output.palm','output.pcd','output.pcl','output.pcx','output.pdb','output.pdf','output.pgx','output.pict','output.jng','output.mng','output.png','output.pnm','output.ps','output.ps2','output.ps3','output.psd','output.raw','output.rgb','output.rgf','output.sgi','output.sixelt','output.sun','output.svg','output.tga','output.thumbnail','output.ptif','output.tiff','output.txt','output.uil','output.uyvy','output.vicar','output.vid','output.viff','output.vips','output.wbmp','output.webp','output.xbm','output.picon','output.xpm','output.xtrn','output.xwd','output.ycbcr','output.ps3mask','output.group4','output.yuv''output.x']



if __name__ == '__main__' :
    if 2 == len(sys.argv) :
        input_file_dir = sys.argv[1]

        if os.path.exists(input_file_dir) :
            if '/' == input_file_dir[-1] :
                input_file_dir = input_file_dir[ : -1]
                
            now_time = time.localtime()
            now_time_string = str(now_time.tm_year) + '_' + str(now_time.tm_mon) + '_' + str(now_time.tm_mday) + '_' + str(now_time.tm_hour) + '_' + str(now_time.tm_min) + '_' + str(now_time.tm_sec)
            crash_dir = input_file_dir + '_' + now_time_string
            crash_dir_crash_sample_dir = crash_dir + '/crash'
            crash_dir_crash_input_dir = crash_dir + '/input'
            crash_dir_crash_output_dir = crash_dir + '/output'

            os.mkdir(crash_dir)
            os.mkdir(crash_dir_crash_sample_dir)
            os.mkdir(crash_dir_crash_input_dir)
            os.mkdir(crash_dir_crash_output_dir)

            if os.path.isdir(input_file_dir) :
                copy_all_file(input_file_dir,crash_dir_crash_input_dir)
            elif os.path.isfile(input_file_dir) :
                copy_file(input_file_dir,crash_dir_crash_input_dir + '/sample')  #  os.system('cp ' + input_file_dir + ' ' + crash_dir_crash_input_dir)

            loop_index = 0
                
            while True :  #  dead loop ..
                crash_index = 0  #  current fuzzing loop get crash total ..
                test_index  = 0  #  current fuzzing loop had test sample total ..
                loop_index += 1  #  fuzzing loop index ..
                output_file_space = 0  #  calcute output files space for save disk space ..
                graphicsmagick_input_file_list = os.listdir(crash_dir_crash_input_dir)
                current_fuzzing_loop_test_files_count = len(graphicsmagick_input_file_list) * len(imagemagick_output_format)
                
                print_output('Fuzzing Write Loop ' + str(loop_index) + ' Start ,Sample Files ' + str(len(graphicsmagick_input_file_list)))

                if 0 == len(graphicsmagick_input_file_list) :
                    print 'Fatal Error : Input File List is Empty ..'

                    exit()
                    
                for graphicsmagick_input_file_index in graphicsmagick_input_file_list :
                    graphicsmagick_input_file_index_path = crash_dir_crash_input_dir + '/' + graphicsmagick_input_file_index
                    disk_space_save_signal = False  #  this flag will exit fuzzing ..
                    
                    for graphicsmagick_output_format_index in imagemagick_output_format :
                        graphicsmagick_output = crash_dir_crash_output_dir + '/' + graphicsmagick_input_file_index + '_' + graphicsmagick_output_format_index
                        graphicsmagick_output_extern_name = get_extern_name(graphicsmagick_output)
                        
                        print_progress(test_index / (current_fuzzing_loop_test_files_count * 1.0),str(test_index) + '/' + str(current_fuzzing_loop_test_files_count)) # + ' Input:' + graphicsmagick_input_file_index_path + ' Output Format:' + graphicsmagick_output_extern_name + '  ')
                        
                        result = run_graphicsmagick_convert(graphicsmagick_input_file_index_path,graphicsmagick_output)  #  it will be block by GraphicsMagick Dead-Loop 
                        
                        if result[0] :  #  catch crash
                            crash_file_path = ''
                            
                            if not None == result[1] :
                                if 'SEGV' == result[1] or 'Memory-Leak' == result[1] :
                                    if check_exist_crash(crash_dir_crash_sample_dir,result[1],result[2]) :
                                        continue
                                        
                                    crash_file_path = result[1] + '-' + result[2] + '_output_' + graphicsmagick_output_extern_name +'_' + str(time.time())
                                else :  #  crash overflow ..
                                    if check_exist_crash(crash_dir_crash_sample_dir,result[1],result[2] + '-' + result[3]) :
                                        continue
                                        
                                    crash_file_path = result[1] + '-' + result[2] + '-' + result[3] + '_output_' + graphicsmagick_output_extern_name +'_' + str(time.time())
                                
                                print_output('Crash (' + str(time.time()) + ') ' + result[1] + ' ' + result[2] + ' ' + graphicsmagick_output_extern_name)
                            else :
                                crash_file_path = 'unknow_crash_output_' + graphicsmagick_output_extern_name + '_' + str(time.time())
                                
                                print_output('Crash (' + str(time.time()) + ') unknow crash' + graphicsmagick_output_extern_name)

                            print_output('Crash Detail :')
                            print_output(graphicsmagick_input_file_index_path + ' ' + graphicsmagick_output)
                            print_output(result[4])
                                
                            copy_file(graphicsmagick_input_file_index_path,crash_dir_crash_sample_dir + '/' + crash_file_path)  #  os.system('cp ' + graphicsmagick_input_file_index_path + ' ' + crash_dir_crash_sample_dir + '/' + crash_file_path)
                                                      
                            crash_index += 1
                        
                        test_index += 1
                        
                        try :
                            output_file_space += os.path.getsize(graphicsmagick_output)
                        except :
                            pass
                        
                        if output_file_space >= MAX_OUTPUT_FILES_DISK_SPACE :
                            disk_space_save_signal = True
                            
                            break
                    
                    if disk_space_save_signal :
                        break
                            
                delete_all_file(crash_dir_crash_input_dir)
                copy_all_file(crash_dir_crash_output_dir,crash_dir_crash_input_dir)
                delete_all_file(crash_dir_crash_output_dir)
                
                print_output('Fuzzing Write Loop ' + str(loop_index) + ' Exit ,Get Crash :' + str(crash_index))
        else :
            print 'Fatal Error : input_file_dir not Exists ..'
    else :
        print 'Using ./graphicsmagick_write_fuzzing.py input_file_dir ..'

