.class public final Landroidx/appcompat/view/menu/pd1;
.super Landroidx/appcompat/view/menu/vb1;
.source "SourceFile"


# instance fields
.field public final synthetic a:Landroid/app/Dialog;

.field public final synthetic b:Landroidx/appcompat/view/menu/rd1;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/rd1;Landroid/app/Dialog;)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/pd1;->b:Landroidx/appcompat/view/menu/rd1;

    iput-object p2, p0, Landroidx/appcompat/view/menu/pd1;->a:Landroid/app/Dialog;

    invoke-direct {p0}, Landroidx/appcompat/view/menu/vb1;-><init>()V

    return-void
.end method


# virtual methods
.method public final a()V
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/pd1;->b:Landroidx/appcompat/view/menu/rd1;

    iget-object v0, v0, Landroidx/appcompat/view/menu/rd1;->n:Landroidx/appcompat/view/menu/ud1;

    invoke-static {v0}, Landroidx/appcompat/view/menu/ud1;->r(Landroidx/appcompat/view/menu/ud1;)V

    iget-object v0, p0, Landroidx/appcompat/view/menu/pd1;->a:Landroid/app/Dialog;

    invoke-virtual {v0}, Landroid/app/Dialog;->isShowing()Z

    move-result v0

    if-eqz v0, :cond_0

    iget-object v0, p0, Landroidx/appcompat/view/menu/pd1;->a:Landroid/app/Dialog;

    invoke-virtual {v0}, Landroid/app/Dialog;->dismiss()V

    :cond_0
    return-void
.end method
