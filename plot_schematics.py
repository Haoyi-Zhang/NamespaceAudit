"""Vector drawing primitives; copied into each independent project generator."""
import argparse
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle, Polygon, Circle, FancyArrowPatch

plt.rcParams.update({'font.family':'STIXGeneral', 'mathtext.fontset':'stix',
                     'font.size':9, 'pdf.fonttype':42, 'ps.fonttype':42,
                     'text.usetex':False, 'axes.unicode_minus':False})
CM = 1 / 2.54

class Drawing:
    def __init__(self, bounds):
        x0,y0,x1,y1 = bounds
        self.fig = plt.figure(figsize=((x1-x0)*CM,(y1-y0)*CM))
        self.ax = self.fig.add_axes([0,0,1,1], xlim=(x0,x1), ylim=(y0,y1))
        self.ax.set_aspect('equal'); self.ax.axis('off')
        self.nodes = {}
        self.labels = []

    def text(self,x,y,label,size=9,ha='center',va='center'):
        artist=self.ax.text(x,y,label,fontsize=size,ha=ha,va=va,
                            linespacing=1.15,clip_on=False,zorder=4)
        self.labels.append([artist,None])
        return artist

    def box(self,name,x,y,w,h,label,dashed=False,shape='rect',size=9):
        style = {'edgecolor':'black','facecolor':'white','linewidth':.55,
                 'linestyle':(0,(4,3)) if dashed else 'solid', 'zorder':2}
        if shape == 'diamond':
            obj = Polygon([(x-w/2,y),(x,y+h/2),(x+w/2,y),(x,y-h/2)],**style)
        elif shape == 'circle': obj = Circle((x,y),w/2,**style)
        else: obj = Rectangle((x-w/2,y-h/2),w,h,**style)
        self.ax.add_patch(obj); self.text(x,y,label,size)
        self.labels[-1][1]=(x-w/2,y-h/2,x+w/2,y+h/2)
        self.nodes[name] = (x,y,w,h,shape)

    def point(self,name,side):
        x,y,w,h,_ = self.nodes[name]
        return {'n':(x,y+h/2),'s':(x,y-h/2),'e':(x+w/2,y),
                'w':(x-w/2,y),'nw':(x-w/2,y+h/2),
                'ne':(x+w/2,y+h/2),'c':(x,y)}[side]

    def line(self,points,dashed=False):
        xs,ys=zip(*points)
        self.ax.plot(xs,ys,color='black',linewidth=.55,
                     linestyle=(0,(4,3)) if dashed else 'solid',zorder=1)

    def arrow(self,p,q,dashed=False,via=()):
        points=[p,*via,q]
        if via:self.line(points[:-1],dashed)
        self.ax.add_patch(FancyArrowPatch(points[-2],points[-1],
                         arrowstyle='-|>',mutation_scale=7.5,linewidth=.55,
                         color='black',shrinkA=0,shrinkB=0,
                         linestyle=(0,(4,3)) if dashed else 'solid',zorder=1))

    def edge(self,a,b,sa='s',sb='n',**kwargs):
        self.arrow(self.point(a,sa),self.point(b,sb),**kwargs)

    def frame(self,x,y,w,h):
        self.ax.add_patch(Rectangle((x,y),w,h,fill=False,edgecolor='black',
                                   linewidth=.55,linestyle=(0,(4,3)),zorder=0))

    def save(self,out,name):
        # Fixed physical canvas: do not enlarge or rasterize the scientific figure.
        self.fig.canvas.draw()
        renderer=self.fig.canvas.get_renderer()
        x0,x1=self.ax.get_xlim();y0,y1=self.ax.get_ylim()
        for artist,node in self.labels:
            b=artist.get_window_extent(renderer).transformed(self.ax.transData.inverted())
            if b.x0<x0-.02 or b.x1>x1+.02 or b.y0<y0-.02 or b.y1>y1+.02:
                raise ValueError(name+': clipped label '+repr(artist.get_text()))
            if node and (b.x0<node[0]-.02 or b.x1>node[2]+.02 or b.y0<node[1]-.02 or b.y1>node[3]+.02):
                raise ValueError(name+': label exceeds node '+repr(artist.get_text()))
        self.fig.savefig(out/(name+'.pdf'),format='pdf',
                         metadata={'Creator':'Python Matplotlib','Producer':None,
                                   'CreationDate':None,'ModDate':None})
        plt.close(self.fig)
def recovery_order(out):
    d=Drawing((0,0,8.6,2.8))
    for i,(lab,policy) in enumerate([
        ('$e_0$\noperational',r'$P_{e_0}:\{a,b\}$'),
        ('$e_1$\nrotation',r'$P_{e_1}:\{a,c\}$'),
        ('$e_2$\nrecovery',r'$P_{e_2}:\{u,v\}$')]):
        x=1.25+3*i
        d.box(str(i),x,1.5,2.1,.95,lab,size=8.5)
        d.text(x,.55,policy,8)
    d.edge('1','0','w','e');d.edge('2','1','w','e')
    d.text(2.75,2.3,'dominates',8);d.text(5.75,2.3,'dominates',8)
    d.save(out,'recovery-order')

def nonlocal_composition(out):
    d=Drawing((0,0,8.6,3.9))
    for x,col in [(1.2,'0'),(3.4,'1')]:
        d.box('r'+col,x,2.8,1,.6,'$r_'+col+'$',size=8.5)
        d.box('c'+col,x,1.25,1,.6,'$c_'+col+'$',size=8.5)
        d.edge('c'+col,'r'+col,'n','s')
        d.text(x-.1,2.02,'requires',7,ha='right')
        d.frame(x-.95,.8,1.85,2.45)
        d.text(x,3.55,'$v$' if col=='0' else '$w$',8.5)
    for name,y,lab in [('a',2.8,r'$Q_r\cap R_r$'),('b',1.25,r'$Q_c\cap R_c$')]:
        d.box(name,5.65,y,.5,.5,'$'+name+'$',shape='circle',size=8)
        d.arrow((4.15,y),d.point(name,'w'))
        d.text(4.75,y+(.4 if name=='a' else -.4),lab,8)
    d.box('s',7.5,2.02,1.8,1.0,'slot $0$\ncapacity $1$',size=8)
    d.edge('a','s','e','w');d.edge('b','s','e','w')
    d.text(4.3,.25,r'$X=(Q_r\cap R_r)\cup(Q_c\cap R_c)=\{a,b\}$',8.5)
    d.save(out,'nonlocal-composition')

def checker_pipeline(out):
    d=Drawing((0,0,17.5,1.6))
    labels=['Strict bounded\nmodel parser','Minimal policy\nsupports','Valid views and\nconflict loci','Antichain DP over\nforced-key unions','Temporal matching\nand classification']
    for i,label in enumerate(labels):
        d.box(str(i),1.65+3.55*i,.8,3,1.0,label,size=8.5)
        if i:d.edge(str(i-1),str(i),'e','w')
    d.save(out,'checker-pipeline')

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--outdir',type=Path,required=True)
    args=parser.parse_args();args.outdir.mkdir(parents=True,exist_ok=True)
    recovery_order(args.outdir);nonlocal_composition(args.outdir);checker_pipeline(args.outdir)
