.class public Landroidx/appcompat/view/menu/e90$b;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroid/widget/AdapterView$OnItemSelectedListener;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Landroidx/appcompat/view/menu/e90;->e()I
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field public final synthetic a:Landroidx/appcompat/view/menu/e90;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/e90;)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/e90$b;->a:Landroidx/appcompat/view/menu/e90;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public onItemSelected(Landroid/widget/AdapterView;Landroid/view/View;IJ)V
    .locals 0

    const/4 p1, -0x1

    if-eq p3, p1, :cond_0

    iget-object p1, p0, Landroidx/appcompat/view/menu/e90$b;->a:Landroidx/appcompat/view/menu/e90;

    iget-object p1, p1, Landroidx/appcompat/view/menu/e90;->c:Landroidx/appcompat/view/menu/wm;

    if-eqz p1, :cond_0

    const/4 p2, 0x0

    invoke-virtual {p1, p2}, Landroidx/appcompat/view/menu/wm;->setListSelectionHidden(Z)V

    :cond_0
    return-void
.end method

.method public onNothingSelected(Landroid/widget/AdapterView;)V
    .locals 0

    return-void
.end method
