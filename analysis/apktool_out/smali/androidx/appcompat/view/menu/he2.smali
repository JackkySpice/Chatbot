.class public final synthetic Landroidx/appcompat/view/menu/he2;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public synthetic m:Landroidx/appcompat/view/menu/yw1;


# direct methods
.method public synthetic constructor <init>(Landroidx/appcompat/view/menu/yw1;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/appcompat/view/menu/he2;->m:Landroidx/appcompat/view/menu/yw1;

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 3

    iget-object v0, p0, Landroidx/appcompat/view/menu/he2;->m:Landroidx/appcompat/view/menu/yw1;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/yw1;->L()Landroidx/appcompat/view/menu/t92;

    move-result-object v1

    invoke-virtual {v1}, Landroidx/appcompat/view/menu/t92;->V0()Z

    move-result v1

    if-nez v1, :cond_0

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/yw1;->l()Landroidx/appcompat/view/menu/lt1;

    move-result-object v0

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/lt1;->L()Landroidx/appcompat/view/menu/ot1;

    move-result-object v0

    const-string v1, "registerTrigger called but app not eligible"

    invoke-virtual {v0, v1}, Landroidx/appcompat/view/menu/ot1;->a(Ljava/lang/String;)V

    return-void

    :cond_0
    new-instance v1, Ljava/lang/Thread;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/yw1;->H()Landroidx/appcompat/view/menu/zz1;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v2, Landroidx/appcompat/view/menu/ne2;

    invoke-direct {v2, v0}, Landroidx/appcompat/view/menu/ne2;-><init>(Landroidx/appcompat/view/menu/zz1;)V

    invoke-direct {v1, v2}, Ljava/lang/Thread;-><init>(Ljava/lang/Runnable;)V

    invoke-virtual {v1}, Ljava/lang/Thread;->start()V

    return-void
.end method
