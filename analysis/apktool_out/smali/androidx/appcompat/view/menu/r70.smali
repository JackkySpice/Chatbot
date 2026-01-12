.class public final synthetic Landroidx/appcompat/view/menu/r70;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic m:Landroidx/appcompat/view/menu/t70;

.field public final synthetic n:Landroidx/appcompat/view/menu/y70$c;

.field public final synthetic o:J

.field public final synthetic p:Landroid/view/KeyEvent;


# direct methods
.method public synthetic constructor <init>(Landroidx/appcompat/view/menu/t70;Landroidx/appcompat/view/menu/y70$c;JLandroid/view/KeyEvent;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/appcompat/view/menu/r70;->m:Landroidx/appcompat/view/menu/t70;

    iput-object p2, p0, Landroidx/appcompat/view/menu/r70;->n:Landroidx/appcompat/view/menu/y70$c;

    iput-wide p3, p0, Landroidx/appcompat/view/menu/r70;->o:J

    iput-object p5, p0, Landroidx/appcompat/view/menu/r70;->p:Landroid/view/KeyEvent;

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 5

    iget-object v0, p0, Landroidx/appcompat/view/menu/r70;->m:Landroidx/appcompat/view/menu/t70;

    iget-object v1, p0, Landroidx/appcompat/view/menu/r70;->n:Landroidx/appcompat/view/menu/y70$c;

    iget-wide v2, p0, Landroidx/appcompat/view/menu/r70;->o:J

    iget-object v4, p0, Landroidx/appcompat/view/menu/r70;->p:Landroid/view/KeyEvent;

    invoke-static {v0, v1, v2, v3, v4}, Landroidx/appcompat/view/menu/t70;->d(Landroidx/appcompat/view/menu/t70;Landroidx/appcompat/view/menu/y70$c;JLandroid/view/KeyEvent;)V

    return-void
.end method
