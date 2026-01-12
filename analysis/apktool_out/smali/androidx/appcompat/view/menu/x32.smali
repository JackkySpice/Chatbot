.class public final Landroidx/appcompat/view/menu/x32;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic m:Landroidx/appcompat/view/menu/p32;

.field public final synthetic n:Landroidx/appcompat/view/menu/p32;

.field public final synthetic o:J

.field public final synthetic p:Z

.field public final synthetic q:Landroidx/appcompat/view/menu/n32;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/n32;Landroidx/appcompat/view/menu/p32;Landroidx/appcompat/view/menu/p32;JZ)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/x32;->q:Landroidx/appcompat/view/menu/n32;

    iput-object p2, p0, Landroidx/appcompat/view/menu/x32;->m:Landroidx/appcompat/view/menu/p32;

    iput-object p3, p0, Landroidx/appcompat/view/menu/x32;->n:Landroidx/appcompat/view/menu/p32;

    iput-wide p4, p0, Landroidx/appcompat/view/menu/x32;->o:J

    iput-boolean p6, p0, Landroidx/appcompat/view/menu/x32;->p:Z

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 7

    iget-object v0, p0, Landroidx/appcompat/view/menu/x32;->q:Landroidx/appcompat/view/menu/n32;

    iget-object v1, p0, Landroidx/appcompat/view/menu/x32;->m:Landroidx/appcompat/view/menu/p32;

    iget-object v2, p0, Landroidx/appcompat/view/menu/x32;->n:Landroidx/appcompat/view/menu/p32;

    iget-wide v3, p0, Landroidx/appcompat/view/menu/x32;->o:J

    iget-boolean v5, p0, Landroidx/appcompat/view/menu/x32;->p:Z

    const/4 v6, 0x0

    invoke-static/range {v0 .. v6}, Landroidx/appcompat/view/menu/n32;->L(Landroidx/appcompat/view/menu/n32;Landroidx/appcompat/view/menu/p32;Landroidx/appcompat/view/menu/p32;JZLandroid/os/Bundle;)V

    return-void
.end method
