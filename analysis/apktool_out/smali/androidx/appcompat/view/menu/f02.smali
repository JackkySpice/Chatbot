.class public final synthetic Landroidx/appcompat/view/menu/f02;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public synthetic m:Landroidx/appcompat/view/menu/zz1;

.field public synthetic n:Landroid/os/Bundle;


# direct methods
.method public synthetic constructor <init>(Landroidx/appcompat/view/menu/zz1;Landroid/os/Bundle;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/appcompat/view/menu/f02;->m:Landroidx/appcompat/view/menu/zz1;

    iput-object p2, p0, Landroidx/appcompat/view/menu/f02;->n:Landroid/os/Bundle;

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 2

    iget-object v0, p0, Landroidx/appcompat/view/menu/f02;->m:Landroidx/appcompat/view/menu/zz1;

    iget-object v1, p0, Landroidx/appcompat/view/menu/f02;->n:Landroid/os/Bundle;

    invoke-virtual {v0, v1}, Landroidx/appcompat/view/menu/zz1;->F(Landroid/os/Bundle;)V

    return-void
.end method
